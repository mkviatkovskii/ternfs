package main

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"testing"

	"github.com/XTXMarkets/ternfs/go/core/bufpool"
	"github.com/XTXMarkets/ternfs/go/core/log"
	"github.com/XTXMarkets/ternfs/go/msgs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

func closeTestFile(t *testing.T) *ternFile {
	t.Helper()
	logger = log.NewLogger(os.Stderr, &log.LoggerOptions{Level: log.ERROR})
	bufPool = bufpool.NewBufPool()
	owner, err := newCloseOwner(uint32(unix.Gettid()))
	if err != nil {
		t.Fatal(err)
	}
	file := &ternFile{
		owner: owner,
		body: &transientFile{
			name:         "pending",
			span:         bufPool.Get(0),
			spanPolicies: msgs.SpanPolicy{Entries: []msgs.SpanPolicyEntry{{MaxSize: 65536}}},
		},
	}
	t.Cleanup(func() { file.Release(context.Background()) })
	return file
}

func closeTestContext(tid uint32) context.Context {
	return fuse.NewContext(context.Background(), &fuse.Caller{Pid: tid})
}

func TestForeignFlushKeepsFileWritable(t *testing.T) {
	file := closeTestFile(t)
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		child.Process.Kill()
		child.Wait()
	})
	ctx := closeTestContext(uint32(child.Process.Pid))
	if errno := file.Flush(ctx); errno != 0 {
		t.Fatalf("foreign Flush: %v", errno)
	}
	if written, errno := file.Write(context.Background(), []byte("remaining"), 0); errno != 0 || written != 9 {
		t.Fatalf("Write after foreign Flush: written=%d errno=%v", written, errno)
	}
}

func TestUnknownFlushCallerDoesNotPublish(t *testing.T) {
	file := closeTestFile(t)
	for _, ctx := range []context.Context{context.Background(), closeTestContext(0)} {
		if errno := file.Flush(ctx); errno != syscall.EIO {
			t.Fatalf("Flush = %v, want EIO", errno)
		}
		if _, ok := file.body.(*transientFile); !ok {
			t.Fatal("unidentified caller changed file state")
		}
	}
}

func TestUnavailableOwnerDoesNotPublish(t *testing.T) {
	file := closeTestFile(t)
	file.owner.Close()
	if errno := file.Flush(closeTestContext(uint32(os.Getpid()))); errno != syscall.EIO {
		t.Fatalf("Flush = %v, want EIO", errno)
	}
	if _, ok := file.body.(*transientFile); !ok {
		t.Fatal("failed identity check changed file state")
	}
}

func TestCreatorExitAbortsFile(t *testing.T) {
	file := closeTestFile(t)
	file.owner.Close()
	proc := t.TempDir()
	writeCloseTask(t, proc, 100, 100, 4)
	var err error
	file.owner, err = newCloseOwnerAt(proc, 100)
	if err != nil {
		t.Fatal(err)
	}
	transient := file.body.(*transientFile)
	if errno := file.Flush(closeTestContext(100)); errno != syscall.EIO {
		t.Fatalf("exiting creator Flush = %v, want EIO", errno)
	}
	if file.owner != nil || transient.span != nil {
		t.Fatal("creator exit retained process or buffer resources")
	}
	if _, errno := file.Write(context.Background(), []byte("late"), 0); errno != syscall.EIO {
		t.Fatalf("Write after creator exit = %v, want EIO", errno)
	}
}

func TestCreatorAbortConcurrentMutation(t *testing.T) {
	logger = log.NewLogger(os.Stderr, &log.LoggerOptions{Level: log.ERROR})
	bufPool = bufpool.NewBufPool()
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	proc := t.TempDir()
	writeCloseTask(t, proc, 100, 100, 4)
	ctx := closeTestContext(100)
	for _, test := range []struct {
		name    string
		mutate  func(*testing.T, *ternFile) syscall.Errno
		aborted syscall.Errno
	}{
		{"Write", func(t *testing.T, file *ternFile) syscall.Errno {
			written, errno := file.Write(ctx, []byte("x"), 0)
			if errno == 0 && written != 1 {
				t.Errorf("Write = %d bytes, want 1", written)
			}
			return errno
		}, syscall.EIO},
		{"Setattr", func(t *testing.T, file *ternFile) syscall.Errno {
			in := &fuse.SetAttrIn{}
			in.Valid = fuse.FATTR_SIZE
			in.Size = 1
			return file.Setattr(ctx, in, &fuse.AttrOut{})
		}, syscall.ENOTSUP},
	} {
		t.Run(test.name, func(t *testing.T) {
			for iteration := range 10000 {
				owner, err := newCloseOwnerAt(proc, 100)
				if err != nil {
					t.Fatal(err)
				}
				transient := &transientFile{
					name:         "pending",
					span:         bufPool.Get(0),
					spanPolicies: msgs.SpanPolicy{Entries: []msgs.SpanPolicyEntry{{MaxSize: 65536}}},
				}
				file := &ternFile{owner: owner, body: transient}
				start := make(chan struct{})
				var workers sync.WaitGroup
				for _, mutate := range []bool{true, false} {
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer func() {
							if panicValue := recover(); panicValue != nil {
								t.Errorf("iteration %d: panic: %v\n%s",
									iteration, panicValue, debug.Stack())
							}
						}()
						<-start
						if mutate {
							if errno := test.mutate(t, file); errno != 0 && errno != test.aborted {
								t.Errorf("mutation = %v", errno)
							}
						} else if errno := file.Flush(ctx); errno != syscall.EIO {
							t.Errorf("creator abort Flush = %v, want EIO", errno)
						}
					}()
				}
				close(start)
				workers.Wait()
				if failed, ok := file.body.(failedTransientFile); !ok || failed.writeError != syscall.EIO {
					t.Errorf("aborted body = %#v", file.body)
				}
				if file.owner != nil || transient.span != nil {
					t.Error("creator abort retained process or buffer resources")
				}
				file.Release(context.Background())
				if t.Failed() {
					return
				}
			}
		})
	}
}

func TestCancelledFlushDoesNotPublish(t *testing.T) {
	file := closeTestFile(t)
	ctx, cancel := context.WithCancel(closeTestContext(uint32(unix.Gettid())))
	cancel()
	if errno := file.Flush(ctx); errno != syscall.EINTR {
		t.Fatalf("cancelled Flush = %v, want EINTR", errno)
	}
	if _, ok := file.body.(*transientFile); !ok {
		t.Fatal("cancelled Flush changed file state")
	}
}

func TestReleaseDiscardsWithoutPublishing(t *testing.T) {
	file := closeTestFile(t)
	transient := file.body.(*transientFile)
	if errno := file.Release(context.Background()); errno != 0 {
		t.Fatalf("Release: %v", errno)
	}
	if file.owner != nil || transient.span != nil {
		t.Fatal("Release retained process or buffer resources")
	}
	if failed, ok := file.body.(failedTransientFile); !ok || failed.writeError != syscall.EIO {
		t.Fatalf("Release body = %#v", file.body)
	}
}

func TestFailedFlushPreservesWriteError(t *testing.T) {
	file := closeTestFile(t)
	transient := file.body.(*transientFile)
	bufPool.Put(transient.span)
	transient.span = nil
	file.body = failedTransientFile{syscall.ENOSPC}
	if errno := file.Flush(context.Background()); errno != syscall.ENOSPC {
		t.Fatalf("Flush = %v, want ENOSPC", errno)
	}
}
