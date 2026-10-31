// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/XTXMarkets/ternfs/go/client"
	"github.com/XTXMarkets/ternfs/go/msgs"
	"github.com/cilium/ebpf"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func (f *ternFile) Flush(ctx context.Context) syscall.Errno {
	logger.Debug("flush file=%v", f.id)
	f.mu.Lock()
	defer f.mu.Unlock()

	if tf, ok := f.body.(*transientFile); ok {
		if tf.name == "" {
			return 0
		}
		if ctx.Err() != nil {
			return syscall.EINTR
		}
		if f.owner != nil {
			caller, ok := fuse.FromContext(ctx)
			if !ok {
				return syscall.EIO
			}
			action, err := f.owner.checkClose(caller.Pid)
			if err != nil {
				logger.Info("cannot identify close file=%v pid=%v: %v", f.id, caller.Pid, err)
				return syscall.EIO
			}
			switch action {
			case closeIgnore:
				logger.Debug("ignoring foreign close file=%v pid=%v", f.id, caller.Pid)
				return 0
			case closeAbort:
				logger.Info("discarding unfinished file=%v after creator exit", f.id)
				f.discardLocked()
				return syscall.EIO
			case closePublish:
			default:
				return syscall.EIO
			}
		} else if closeMap == nil {
			return syscall.EIO
		}
		if closeMap != nil {
			var closes uint64
			if err := closeMap.LookupAndDelete(uint64(f.id), &closes); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					logger.Info("flush file=%v no close key", f.id)
					return 0
				}
				logger.RaiseAlert("Could not lookup key in close map for file %v: %v", f.id, err)
				return syscall.EIO
			}
			if closes == 0 {
				logger.RaiseAlert("Unexpected zero close count in close map for file %v", f.id)
				return syscall.EIO
			}
		}
	}
	return f.publishLocked()
}

func (f *ternFile) publish() syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publishLocked()
}

func (f *ternFile) publishLocked() syscall.Errno {
	switch tf := f.body.(type) {
	case *transientFile:
		if err := f.writeSpan(); err != 0 {
			return err
		}
		req := msgs.LinkFileReq{
			FileId: f.id, Cookie: tf.cookie, OwnerId: tf.dir, Name: tf.name,
		}
		if err := shardRequest(tf.dir.Shard(), &req, &msgs.LinkFileResp{}); err != 0 {
			f.body = failedTransientFile{err}
			return err
		}
		fr, err := c.NewFileReader(logger, f.id)
		if err != nil {
			f.body = failedTransientFile{ternErrToErrno(err)}
			return ternErrToErrno(err)
		}
		f.body = fr
		if f.owner != nil {
			f.owner.Close()
			f.owner = nil
		}
		return 0
	case *client.FileReader:
		return 0
	case failedTransientFile:
		return tf.writeError
	default:
		panic(fmt.Errorf("bad file type %T", f.body))
	}
}

func (f *ternFile) discardLocked() {
	if tf, ok := f.body.(*transientFile); ok {
		bufPool.Put(tf.span)
		tf.span = nil
		f.body = failedTransientFile{syscall.EIO}
	}
	if f.owner != nil {
		f.owner.Close()
		f.owner = nil
	}
}

func (f *ternFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discardLocked()
	return 0
}
