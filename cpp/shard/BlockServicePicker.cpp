// Copyright 2025 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include "BlockServicePicker.hpp"

#include "Bincode.hpp"
#include "MsgsGen.hpp"
#include "Time.hpp"
#include "Msgs.hpp"
#include "BlockServicesCacheDB.hpp"
#include <algorithm>
#include <unordered_set>

namespace {
    inline uint16_t lcKey(uint8_t locationId, uint8_t storageClass) {
        return (uint16_t(locationId) << 8) | uint16_t(storageClass);
    }

    inline bool blockServiceIsWritable(const BlockServiceCache& bs, Duration writableDelay, uint64_t minSpaceRequiredForWrite) {
        return bs.availableBytes > minSpaceRequiredForWrite && blockServiceFlagsWritable(bs.flags) && ternNow() - bs.firstSeen > writableDelay;
    }

    inline double throughputBytesPerSec(uint64_t accumulatedBytes, Duration elapsed) {
        double elapsedSec = static_cast<double>(elapsed.ns) / 1'000'000'000.0;
        return static_cast<double>(accumulatedBytes) * ShardId::SHARD_COUNT / elapsedSec;
    }

    inline double ratioFromThroughput(uint64_t maxDriveThroughput, uint64_t numDrives, double throughput) {
        if (maxDriveThroughput == 0 || numDrives == 0 || throughput <= 0.0) return 1.0;
        double ratio = static_cast<double>(maxDriveThroughput) * numDrives / throughput;
        return ratio < 1.0 ? 1.0 : ratio;
    }

    // Cap every disk's weight to globalMinSvcWeight * maxFdRatio across the (loc, sc).
    // At ratio = 1.0 this makes per-disk weights uniform, so FD weights become
    // proportional to disk count and per-disk pick probability becomes uniform.
    // At high ratio (low load) the cap is large and original capacity-proportional
    // weights flow through unchanged.
    void applyGlobalCap(
        BlockServicePicker::LocationStorageInfo& lsInfo,
        std::unordered_map<uint64_t, BlockServicePicker::State::ServiceLookup>& serviceToFdInfo,
        double maxFdRatio
    ) {
        if (maxFdRatio < 1.0 || lsInfo.failureDomains.empty()) return;

        uint64_t minSvcWeight = UINT64_MAX;
        for (const auto& fd : lsInfo.failureDomains) {
            for (const auto& svc : fd.services) {
                if (svc.availableBytes > 0) {
                    minSvcWeight = std::min(minSvcWeight, svc.availableBytes);
                }
            }
        }
        if (minSvcWeight == UINT64_MAX) return;

        double svcCapD = static_cast<double>(minSvcWeight) * maxFdRatio;
        uint64_t svcCap = (svcCapD >= static_cast<double>(UINT64_MAX))
            ? UINT64_MAX : static_cast<uint64_t>(svcCapD);
        if (svcCap == 0) svcCap = 1;

        uint64_t newLsTotal = 0;
        for (auto& fd : lsInfo.failureDomains) {
            uint64_t newFdTotal = 0;
            for (auto& svc : fd.services) {
                if (svc.availableBytes == 0) continue;
                if (svc.availableBytes > svcCap) {
                    svc.availableBytes = svcCap;
                    serviceToFdInfo[svc.id.u64].weight = svcCap;
                }
                newFdTotal += svc.availableBytes;
            }
            fd.totalWeight = newFdTotal;
            newLsTotal += newFdTotal;
        }
        lsInfo.totalWeight = newLsTotal;
    }

    static constexpr size_t FAILURE_DOMAIN_NAME_SIZE = decltype(FailureDomain::name)::STATIC_SIZE;

    struct PickResult {
        BlockServiceId serviceId;
        std::array<uint8_t, FAILURE_DOMAIN_NAME_SIZE> fdData;
    };

    // Sequential weighted sampling without replacement over failure domains.
    // For each of `needed` draws: pick an FD with probability proportional to its
    // remaining weight, then weighted-sample a non-blacklisted disk in that FD,
    // then drop the FD from the live set.
    // Caller guarantees: at least `needed` FDs have positive weight in fdWeights.
    void sequentialWeightedPick(
        const std::vector<BlockServicePicker::FailureDomainInfo>& failureDomains,
        const std::vector<uint64_t>& fdWeights,
        uint8_t needed,
        const std::unordered_set<uint64_t>& blacklistedServices,
        RandomGenerator& rng,
        std::vector<PickResult>& results
    ) {
        results.clear();
        results.reserve(needed);

        std::vector<size_t> live;
        std::vector<uint64_t> liveWeights;
        live.reserve(failureDomains.size());
        liveWeights.reserve(failureDomains.size());
        uint64_t totalWeight = 0;
        for (size_t i = 0; i < failureDomains.size(); i++) {
            if (fdWeights[i] > 0) {
                live.push_back(i);
                liveWeights.push_back(fdWeights[i]);
                totalWeight += fdWeights[i];
            }
        }

        for (uint8_t k = 0; k < needed; k++) {
            uint64_t target = rng.generate64() % totalWeight;
            size_t chosen = 0;
            uint64_t cumulative = 0;
            for (size_t i = 0; i < live.size(); i++) {
                cumulative += liveWeights[i];
                if (target < cumulative) {
                    chosen = i;
                    break;
                }
            }

            const auto& fdInfo = failureDomains[live[chosen]];
            uint64_t fdTarget = rng.generate64() % liveWeights[chosen];
            uint64_t svcCumulative = 0;
            for (const auto& svc : fdInfo.services) {
                if (blacklistedServices.contains(svc.id.u64)) continue;
                svcCumulative += svc.availableBytes;
                if (fdTarget < svcCumulative) {
                    results.push_back({svc.id, fdInfo.failureDomain.name.data});
                    break;
                }
            }

            totalWeight -= liveWeights[chosen];
            live[chosen] = live.back();
            liveWeights[chosen] = liveWeights.back();
            live.pop_back();
            liveWeights.pop_back();
        }

        ALWAYS_ASSERT(results.size() == needed);
    }
}

BlockServicePicker::BlockServicePicker(Logger& logger, std::shared_ptr<XmonAgent>& xmon, Duration writableDelay,
                                       uint64_t hddDriveThroughput, uint64_t flashDriveThroughput,
                                       uint64_t minSpaceRequiredForWrite)
    : _state(nullptr), _rawState(nullptr), _rng(ternNow().ns), _env(logger, xmon, "block_service_picker"),
      _writableDelay(writableDelay),
      _hddDriveThroughput(hddDriveThroughput), _flashDriveThroughput(flashDriveThroughput),
      _minSpaceRequiredForWrite(minSpaceRequiredForWrite) {}

void BlockServicePicker::update(
    const std::unordered_map<uint64_t, BlockServiceCache>& allBlockServices
) {
    auto next = std::make_shared<State>();

    std::unordered_map<uint16_t, std::unordered_map<std::string, size_t>> grouped;
    std::unordered_set<uint16_t> distinctBlockServiceTypeLoc;

    for (const auto& [id, bs] : allBlockServices) {
        distinctBlockServiceTypeLoc.insert(lcKey(bs.locationId, bs.storageClass));
        if (!blockServiceIsWritable(bs, _writableDelay, _minSpaceRequiredForWrite)) continue;

        uint16_t key = lcKey(bs.locationId, bs.storageClass);
        std::string fdStr(reinterpret_cast<const char*>(bs.failureDomain.data()), bs.failureDomain.size());

        auto& lsInfo = next->byLocClass[key];

        auto& fdMap = grouped[key];
        auto [it, inserted] = fdMap.try_emplace(fdStr, lsInfo.failureDomains.size());
        if (inserted) {
            lsInfo.failureDomains.emplace_back(
                FailureDomainInfo{
                    FailureDomain{BincodeFixedBytes<16>{fdStr.data(), fdStr.size()}},
                    {},
                    0
                });
        }

        FailureDomainInfo& fdInfo = lsInfo.failureDomains[it->second];
        fdInfo.services.emplace_back(BlockServiceInfo{BlockServiceId(id), bs.availableBytes});
        fdInfo.totalWeight += bs.availableBytes;
        lsInfo.totalWeight += bs.availableBytes;

        next->serviceToFdInfo[id] = {key, it->second, bs.availableBytes};
    }

    for (auto key : distinctBlockServiceTypeLoc) {
        auto otherKey = (key & 0xFF) == HDD_STORAGE
            ? (key & 0xFF00) | FLASH_STORAGE
            : (key & 0xFF00) | HDD_STORAGE;
        if (!distinctBlockServiceTypeLoc.contains(otherKey)) {
            next->needsFallback.insert(otherKey);
        }
    }

    _rawState.store(next, std::memory_order_release);

    auto clamped = std::make_shared<State>(*next);

    auto nowNs = ternNow().ns;
    {
        std::lock_guard lock(_statsMutex);
        for (auto& [key, lsInfo] : clamped->byLocClass) {
            auto& stats = _locStorageStats[key];

            uint64_t totalServices = 0;
            for (const auto& fd : lsInfo.failureDomains) {
                totalServices += fd.services.size();
            }

            uint8_t storageClass = key & 0xFF;
            uint64_t maxDriveThroughput = (storageClass == FLASH_STORAGE) ? _flashDriveThroughput : _hddDriveThroughput;

            double ratio = 0.0;
            uint64_t lastEstimate = stats.lastThroughputEstimate.load(std::memory_order_relaxed);
            if (maxDriveThroughput > 0 && totalServices > 0) {
                uint64_t accumulated = stats.throughputBytes.load(std::memory_order_relaxed);
                TernTime lastRecalcTime(stats.lastRecalcTimeNs.load(std::memory_order_relaxed));
                Duration elapsed = TernTime(nowNs) - lastRecalcTime;

                if (lastEstimate == 0) {
                    // First update for this lcKey — assume max load
                    lastEstimate = maxDriveThroughput * totalServices;
                } else if (elapsed >= 1_sec && accumulated > 0) {
                    lastEstimate = static_cast<uint64_t>(throughputBytesPerSec(accumulated, elapsed));
                }

                stats.lastThroughputEstimate.store(lastEstimate, std::memory_order_relaxed);
                stats.throughputBytes.store(0, std::memory_order_relaxed);
                stats.lastRecalcTimeNs.store(nowNs, std::memory_order_relaxed);

                ratio = ratioFromThroughput(maxDriveThroughput, totalServices, static_cast<double>(lastEstimate));
            }

            applyGlobalCap(lsInfo, clamped->serviceToFdInfo, ratio);

            uint64_t maxW = 0, minW = UINT64_MAX;
            for (const auto& fd : lsInfo.failureDomains) {
                maxW = std::max(maxW, fd.totalWeight);
                minW = std::min(minW, fd.totalWeight);
            }

            stats.writableFailureDomains.store(lsInfo.failureDomains.size(), std::memory_order_relaxed);
            stats.writableBlockServices.store(totalServices, std::memory_order_relaxed);
            stats.maxWeight.store(maxW, std::memory_order_relaxed);
            stats.minWeight.store(lsInfo.failureDomains.empty() ? 0 : minW, std::memory_order_relaxed);
            stats.numDrives = totalServices;
        }

        // Reset stats for lcKeys that no longer have any services — otherwise
        // numDrives stays stale and the spike path computes bogus loadPerDrive.
        for (auto& [key, stats] : _locStorageStats) {
            if (clamped->byLocClass.contains(key)) continue;
            stats.writableFailureDomains.store(0, std::memory_order_relaxed);
            stats.writableBlockServices.store(0, std::memory_order_relaxed);
            stats.maxWeight.store(0, std::memory_order_relaxed);
            stats.minWeight.store(0, std::memory_order_relaxed);
            stats.lastThroughputEstimate.store(0, std::memory_order_relaxed);
            stats.throughputBytes.store(0, std::memory_order_relaxed);
            stats.numDrives = 0;
        }
    }

    _state.store(clamped, std::memory_order_release);
}

TernError BlockServicePicker::pick(
    uint8_t locationId,
    uint8_t storageClass,
    uint8_t needed,
    const std::vector<BlacklistEntry>& blacklist,
    std::vector<BlockServiceId>& out,
    uint64_t blockSize
) const {
    auto state = _state.load(std::memory_order_acquire);
    if (!state || needed == 0) {
        LOG_DEBUG(_env, "pick failed: state=%s needed=%s",
            state != nullptr, (int)needed);
        return TernError::COULD_NOT_PICK_BLOCK_SERVICES;
    }

    uint16_t key = lcKey(locationId, storageClass);

    if (state->needsFallback.contains(key)) {
        storageClass = storageClass == HDD_STORAGE ? FLASH_STORAGE : HDD_STORAGE;
        key = lcKey(locationId, storageClass);
    }

    if (blockSize > 0) {
        ALWAYS_ASSERT(blockSize <= MAXIMUM_SPAN_SIZE,
            "blockSize %s > MAXIMUM_SPAN_SIZE %s", blockSize, MAXIMUM_SPAN_SIZE);
        std::lock_guard lock(_statsMutex);
        auto& stats = _locStorageStats[key];
        uint64_t totalBytes = blockSize * needed;
        uint64_t accumulated = stats.throughputBytes.fetch_add(totalBytes, std::memory_order_relaxed) + totalBytes;

        TernTime lastRecalcTime(stats.lastRecalcTimeNs.load(std::memory_order_relaxed));
        TernTime now = ternNow();
        Duration elapsed = now - lastRecalcTime;
        uint64_t lastEstimate = stats.lastThroughputEstimate.load(std::memory_order_relaxed);

        // Trigger a recalc if we've seen a sustained spike above the last estimate.
        // We don't react to load reductions — the periodic recalc in update() will
        // restore throughput ratios and unblock any clamped FDs.
        bool spikeTriggered = elapsed >= 1_sec && lastEstimate > 0 &&
            throughputBytesPerSec(accumulated, elapsed) > static_cast<double>(lastEstimate) * 1.1;

        if (spikeTriggered && _recalcMutex.try_lock()) {
            std::unique_lock recalcLock(_recalcMutex, std::adopt_lock);
            lastRecalcTime = TernTime(stats.lastRecalcTimeNs.load(std::memory_order_relaxed));
            elapsed = now - lastRecalcTime;
            accumulated = stats.throughputBytes.load(std::memory_order_relaxed);
            if (elapsed > 1_sec) {
                double currentThroughput = throughputBytesPerSec(accumulated, elapsed);
                uint64_t numDrives = stats.numDrives;
                uint8_t sc = key & 0xFF;
                uint64_t maxDriveThroughput = (sc == FLASH_STORAGE) ? _flashDriveThroughput : _hddDriveThroughput;

                double newRatio = ratioFromThroughput(maxDriveThroughput, numDrives, currentThroughput);

                auto rawState = _rawState.load(std::memory_order_acquire);
                if (rawState) {
                    auto expected = _state.load(std::memory_order_acquire);
                    auto newState = std::make_shared<State>(*expected);

                    auto rawIt = rawState->byLocClass.find(key);
                    if (rawIt != rawState->byLocClass.end()) {
                        // Drop stale entries for this lcKey before re-populating from rawState:
                        // services removed since the last update() still linger here with a
                        // now-invalid fdIndex and would corrupt blacklist weight adjustments.
                        for (auto svcIt = newState->serviceToFdInfo.begin(); svcIt != newState->serviceToFdInfo.end();) {
                            if (svcIt->second.lcKey == key) {
                                svcIt = newState->serviceToFdInfo.erase(svcIt);
                            } else {
                                ++svcIt;
                            }
                        }
                        newState->byLocClass[key] = rawIt->second;
                        auto& lsInfoRef = newState->byLocClass[key];
                        for (const auto& fd : lsInfoRef.failureDomains) {
                            for (const auto& svc : fd.services) {
                                auto rawSvcIt = rawState->serviceToFdInfo.find(svc.id.u64);
                                if (rawSvcIt != rawState->serviceToFdInfo.end()) {
                                    newState->serviceToFdInfo[svc.id.u64] = rawSvcIt->second;
                                }
                            }
                        }

                        applyGlobalCap(lsInfoRef, newState->serviceToFdInfo, newRatio);

                        uint64_t maxW = 0, minW = UINT64_MAX;
                        for (const auto& fd : lsInfoRef.failureDomains) {
                            maxW = std::max(maxW, fd.totalWeight);
                            minW = std::min(minW, fd.totalWeight);
                        }
                        stats.maxWeight.store(maxW, std::memory_order_relaxed);
                        stats.minWeight.store(lsInfoRef.failureDomains.empty() ? 0 : minW, std::memory_order_relaxed);

                        _state.compare_exchange_strong(expected, newState, std::memory_order_release);

                        state = _state.load(std::memory_order_acquire);
                    }
                }

                stats.throughputBytes.store(0, std::memory_order_relaxed);
                stats.lastRecalcTimeNs.store(now.ns, std::memory_order_relaxed);
                stats.lastThroughputEstimate.store(static_cast<uint64_t>(currentThroughput), std::memory_order_relaxed);
            }
        }
    }

    auto it = state->byLocClass.find(key);

    if (it != state->byLocClass.end()) {
        const auto& lsInfo = it->second;

        std::unordered_set<uint64_t> blacklistedServices;
        for (const auto& b : blacklist) {
            blacklistedServices.insert(b.blockService.u64);
        }

        std::vector<uint64_t> fdWeights;
        std::unordered_set<uint64_t> actuallyBlacklistedServices;
        fdWeights.reserve(lsInfo.failureDomains.size());

        for (const auto& fdInfo : lsInfo.failureDomains) {
            uint64_t adjustedWeight = fdInfo.totalWeight;
            for (const auto& b : blacklist) {
                if (b.failureDomain == fdInfo.failureDomain) {
                    adjustedWeight = 0;
                    break;
                }
            }
            fdWeights.emplace_back(adjustedWeight);
        }

        for(const auto& blacklistEntry : blacklist) {
            auto svcIt = state->serviceToFdInfo.find(blacklistEntry.blockService.u64);
            if (svcIt != state->serviceToFdInfo.end()) {
                const auto& svcInfo = svcIt->second;
                if (fdWeights[svcInfo.fdIndex] == 0) continue;
                if (svcInfo.lcKey == key) {
                    actuallyBlacklistedServices.insert(blacklistEntry.blockService.u64);
                    fdWeights[svcInfo.fdIndex] -= svcInfo.weight;
                }
            }
        }

        size_t liveFdCount = 0;
        for (uint64_t w : fdWeights) {
            if (w > 0) liveFdCount++;
        }

        if (liveFdCount >= needed) {
            std::vector<PickResult> results;
            sequentialWeightedPick(lsInfo.failureDomains, fdWeights, needed,
                                   actuallyBlacklistedServices, _rng, results);
            out.clear();
            out.reserve(needed);
            std::lock_guard lock(_statsMutex);
            for (const auto& r : results) {
                out.push_back(r.serviceId);
                _blockServiceStats[r.serviceId.u64].fetch_add(1, std::memory_order_relaxed);
                std::string fdStr(reinterpret_cast<const char*>(r.fdData.data()), r.fdData.size());
                _failureDomainStats[fdStr].fetch_add(1, std::memory_order_relaxed);
            }
            _locStorageStats[key].totalPicks.fetch_add(needed, std::memory_order_relaxed);
            return TernError::NO_ERROR;
        }
    }

    if (_env.shouldLog(LogLevel::LOG_DEBUG)) {
        auto it2 = state->byLocClass.find(key);
        if (it2 == state->byLocClass.end()) {
            LOG_DEBUG(_env, "pick failed: no entry for location=%s storageClass=%s (key=0x%s), byLocClass has %s entries, needsFallback has %s entries",
                (int)locationId, (int)storageClass, key, state->byLocClass.size(), state->needsFallback.size());
            for (const auto& [k, lsInfo] : state->byLocClass) {
                LOG_DEBUG(_env, "  byLocClass key=0x%s: failureDomains=%s totalWeight=%s",
                    k, lsInfo.failureDomains.size(), lsInfo.totalWeight);
            }
        } else {
            const auto& lsInfo = it2->second;
            size_t totalServices = 0;
            for (const auto& fd : lsInfo.failureDomains) {
                totalServices += fd.services.size();
            }
            LOG_DEBUG(_env, "pick failed: location=%s storageClass=%s needed=%s blacklist=%s failureDomains=%s totalServices=%s totalWeight=%s",
                (int)locationId, (int)storageClass, (int)needed, blacklist.size(), lsInfo.failureDomains.size(), totalServices, lsInfo.totalWeight);
            for (size_t fdIdx = 0; fdIdx < lsInfo.failureDomains.size(); fdIdx++) {
                const auto& fdInfo = lsInfo.failureDomains[fdIdx];
                LOG_DEBUG(_env, "  fd[%s]: services=%s totalWeight=%s",
                    fdIdx, fdInfo.services.size(), fdInfo.totalWeight);
            }
        }
    }
    out.clear();
    return TernError::COULD_NOT_PICK_BLOCK_SERVICES;
}

BlockServicePicker::StatsSnapshot BlockServicePicker::getStats() const {
    StatsSnapshot snapshot;
    std::lock_guard lock(_statsMutex);

    for (const auto& [key, stats] : _locStorageStats) {
        uint64_t numDrives = stats.numDrives;
        uint64_t lastEstimate = stats.lastThroughputEstimate.load(std::memory_order_relaxed);
        uint8_t sc = key & 0xFF;
        uint64_t maxDriveThroughput = (sc == FLASH_STORAGE) ? _flashDriveThroughput : _hddDriveThroughput;
        double effectiveMaxRatio = ratioFromThroughput(maxDriveThroughput, numDrives, static_cast<double>(lastEstimate));

        snapshot.locStorage.push_back({
            key,
            stats.totalPicks.load(std::memory_order_relaxed),
            stats.writableFailureDomains.load(std::memory_order_relaxed),
            stats.writableBlockServices.load(std::memory_order_relaxed),
            stats.maxWeight.load(std::memory_order_relaxed),
            stats.minWeight.load(std::memory_order_relaxed),
            effectiveMaxRatio,
            lastEstimate
        });
    }

    uint64_t minPicks = UINT64_MAX, maxPicks = 0;
    for (const auto& [id, stats] : _blockServiceStats) {
        uint64_t picks = stats.load(std::memory_order_relaxed);
        snapshot.blockServices.push_back({id, picks});
        if (picks > 0) {
            minPicks = std::min(minPicks, picks);
            maxPicks = std::max(maxPicks, picks);
        }
    }
    snapshot.minServicePicks = (minPicks == UINT64_MAX) ? 0 : minPicks;
    snapshot.maxServicePicks = maxPicks;

    uint64_t minFdPicks = UINT64_MAX, maxFdPicks = 0;
    for (const auto& [fd, stats] : _failureDomainStats) {
        uint64_t picks = stats.load(std::memory_order_relaxed);
        snapshot.failureDomains.push_back({fd, picks});
        if (picks > 0) {
            minFdPicks = std::min(minFdPicks, picks);
            maxFdPicks = std::max(maxFdPicks, picks);
        }
    }
    snapshot.minFdPicks = (minFdPicks == UINT64_MAX) ? 0 : minFdPicks;
    snapshot.maxFdPicks = maxFdPicks;

    return snapshot;
}

void BlockServicePicker::resetStats() {
    std::lock_guard lock(_statsMutex);

    for (auto& [key, stats] : _locStorageStats) {
        stats.totalPicks.store(0, std::memory_order_relaxed);
    }

    for (auto& [id, stats] : _blockServiceStats) {
        stats.store(0, std::memory_order_relaxed);
    }

    for (auto& [fd, stats] : _failureDomainStats) {
        stats.store(0, std::memory_order_relaxed);
    }
}
