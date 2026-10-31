// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type closeAction uint8

const (
	closeIgnore closeAction = iota
	closePublish
	closeAbort
)

type closeOwner struct {
	mu      sync.Mutex
	proc    string
	tgid    uint32
	creator *os.Root
}

func newCloseOwner(tid uint32) (*closeOwner, error) {
	self, err := os.OpenRoot("/proc/self")
	if err != nil {
		return nil, err
	}
	defer self.Close()
	status, err := readCloseProc(self, "status")
	if err != nil {
		return nil, err
	}
	if err := checkCloseNamespace(status, uint32(os.Getpid())); err != nil {
		return nil, err
	}
	return newCloseOwnerAt("/proc", tid)
}

func checkCloseNamespace(status string, pid uint32) error {
	found := false
	for line := range strings.SplitSeq(status, "\n") {
		if !strings.HasPrefix(line, "NStgid:") {
			continue
		}
		fields := strings.Fields(line)
		if found || len(fields) != 2 || fields[0] != "NStgid:" ||
			fields[1] != strconv.FormatUint(uint64(pid), 10) {
			return fmt.Errorf("procfs does not match the daemon PID namespace")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("procfs does not expose the daemon PID namespace")
	}
	return nil
}

func newCloseOwnerAt(proc string, tid uint32) (*closeOwner, error) {
	task, tgid, err := openCloseTask(proc, tid)
	if err != nil {
		return nil, err
	}
	defer task.Close()
	creator, err := os.OpenRoot(filepath.Join(proc, strconv.FormatUint(uint64(tgid), 10)))
	if err != nil {
		return nil, err
	}
	// Revalidate the pinned caller after opening its process by number.
	if _, err := readCloseStat(task, tid); err != nil {
		creator.Close()
		return nil, err
	}
	return &closeOwner{proc: proc, tgid: tgid, creator: creator}, nil
}

func (o *closeOwner) checkClose(tid uint32) (closeAction, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	original, err := o.creator.Stat(".")
	if err != nil {
		return closeIgnore, err
	}
	task, tgid, err := openCloseTask(o.proc, tid)
	if err != nil {
		return closeIgnore, err
	}
	defer task.Close()
	same := tgid == o.tgid
	if same {
		current, err := os.Stat(filepath.Join(o.proc, strconv.FormatUint(uint64(tgid), 10)))
		if err != nil {
			return closeIgnore, err
		}
		same = os.SameFile(original, current)
	}
	// A reused numeric PID cannot satisfy this read through the original task handle.
	stat, err := readCloseStat(task, tid)
	if err != nil {
		return closeIgnore, err
	}
	if !same {
		return closeIgnore, nil
	}
	// PF_EXITING is set in do_exit before exit_files; it is not an mm identity test.
	if stat.flags&0x4 != 0 {
		return closeAbort, nil
	}
	return closePublish, nil
}

func (o *closeOwner) Close() {
	if o != nil && o.creator != nil {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.creator.Close()
	}
}

func openCloseTask(proc string, tid uint32) (*os.Root, uint32, error) {
	if tid == 0 {
		return nil, 0, fmt.Errorf("invalid close caller TID 0")
	}
	task, err := os.OpenRoot(filepath.Join(proc, strconv.FormatUint(uint64(tid), 10)))
	if err != nil {
		return nil, 0, err
	}
	data, err := readCloseProc(task, "status")
	var tgid uint32
	if err == nil {
		tgid, err = parseCloseTGID(data)
	}
	if err != nil {
		task.Close()
		return nil, 0, err
	}
	return task, tgid, nil
}

func readCloseProc(root *os.Root, name string) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	const maxSize = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSize {
		return "", fmt.Errorf("proc %s exceeds %d bytes", name, maxSize)
	}
	return string(data), nil
}

func parseCloseTGID(data string) (uint32, error) {
	var tgid uint32
	for line := range strings.SplitSeq(data, "\n") {
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		fields := strings.Fields(line)
		if tgid != 0 || len(fields) != 2 || fields[0] != "Tgid:" {
			return 0, fmt.Errorf("malformed proc Tgid")
		}
		value, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || value == 0 {
			return 0, fmt.Errorf("invalid proc Tgid %q", fields[1])
		}
		tgid = uint32(value)
	}
	if tgid == 0 {
		return 0, fmt.Errorf("missing proc Tgid")
	}
	return tgid, nil
}

type closeTaskStat struct {
	flags uint64
	start uint64
}

func readCloseStat(task *os.Root, tid uint32) (closeTaskStat, error) {
	data, err := readCloseProc(task, "stat")
	if err != nil {
		return closeTaskStat{}, err
	}
	return parseCloseStat(data, tid)
}

func parseCloseStat(data string, tid uint32) (closeTaskStat, error) {
	open, close := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if open < 2 || close < open || data[open-1] != ' ' ||
		close+1 >= len(data) || data[close+1] != ' ' {
		return closeTaskStat{}, fmt.Errorf("malformed proc stat command")
	}
	pid, err := strconv.ParseUint(data[:open-1], 10, 32)
	if err != nil || pid == 0 || pid != uint64(tid) {
		return closeTaskStat{}, fmt.Errorf("proc stat PID does not match TID %d", tid)
	}
	fields := strings.Fields(data[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 ||
		!strings.Contains("RSDZTtXxKWPI", fields[0]) {
		return closeTaskStat{}, fmt.Errorf("malformed proc stat fields")
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return closeTaskStat{}, fmt.Errorf("invalid proc stat flags: %w", err)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return closeTaskStat{}, fmt.Errorf("invalid proc stat starttime: %w", err)
	}
	return closeTaskStat{flags: flags, start: start}, nil
}
