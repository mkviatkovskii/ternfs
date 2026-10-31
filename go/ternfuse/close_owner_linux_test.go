// Copyright 2026 XTX Markets Technologies Limited
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func closeStatFixture(tid uint32, name string, flags uint64) string {
	return fmt.Sprintf(
		"%d (%s) S 1 2 3 4 5 %d 0 0 0 0 0 0 0 0 0 0 1 0 12345"+
			" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
		tid, name, flags)
}

func TestCloseOwnerProcNamespace(t *testing.T) {
	for _, test := range []struct {
		status string
		ok     bool
	}{
		{"Name: daemon\nNStgid:\t42\n", true},
		{"NStgid:\t1000\t42\n", false},
		{"NStgid:\t42\t42\n", false},
		{"NStgid:\t43\n", false},
		{"Tgid:\t42\n", false},
		{"NStgid:\t42\nNStgid:\t42\n", false},
		{"NStgid:\tinvalid\n", false},
		{"NStgid:extra 42\n", false},
	} {
		err := checkCloseNamespace(test.status, 42)
		if (err == nil) != test.ok {
			t.Errorf("namespace %q: err=%v", test.status, err)
		}
	}
}

func TestCloseOwnerParseTGID(t *testing.T) {
	for _, test := range []struct {
		status string
		want   uint32
	}{
		{"Name:\ta task (name)\nTgid:\t42\nPid:\t43\n", 42},
		{"Tgid: 42\n", 42},
		{"", 0},
		{"Pid:\t42\n", 0},
		{"Tgid:\n", 0},
		{"Tgid: 0\n", 0},
		{"Tgid: -1\n", 0},
		{"Tgid: 4294967296\n", 0},
		{"Tgid: garbage\n", 0},
		{"Tgid: 42 extra\n", 0},
		{"Tgid: 42\nTgid: 42\n", 0},
	} {
		t.Run(strconv.Quote(test.status), func(t *testing.T) {
			got, err := parseCloseTGID(test.status)
			if got != test.want || (err != nil) != (test.want == 0) {
				t.Fatalf("TGID = %d, %v; want %d", got, err, test.want)
			}
		})
	}
}

func TestCloseOwnerParseStat(t *testing.T) {
	for _, name := range []string{"plain", "with spaces", "a (b)) c(", "a\nb"} {
		stat, err := parseCloseStat(closeStatFixture(43, name, 4194308), 43)
		if err != nil || stat.flags != 4194308 || stat.start != 12345 {
			t.Fatalf("name %q: stat = %+v, %v", name, stat, err)
		}
	}
	valid := closeStatFixture(43, "task", 4)
	for _, data := range []string{
		"", "43", "43 task S 1 2 3 4 5 4", "43 (task)",
		"43 (task) S 1 2 3 4 5 4",
		strings.Replace(valid, "43 (", "44 (", 1),
		strings.Replace(valid, ") S ", ") INVALID ", 1),
		strings.Replace(valid, "5 4 ", "5 -4 ", 1),
		strings.Replace(valid, "5 4 ", "5 18446744073709551616 ", 1),
		strings.Replace(valid, "12345", "invalid", 1),
	} {
		if _, err := parseCloseStat(data, 43); err == nil {
			t.Errorf("accepted malformed stat %q", data)
		}
	}
}

func writeCloseTask(t *testing.T, proc string, tid, tgid uint32, flags uint64) {
	t.Helper()
	dir := filepath.Join(proc, strconv.FormatUint(uint64(tid), 10))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeCloseProc(t, dir, "status", fmt.Sprintf("Tgid:\t%d\n", tgid))
	writeCloseProc(t, dir, "stat", closeStatFixture(tid, "task (with) spaces", flags))
}

func writeCloseProc(t *testing.T, dir, name, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCloseOwnerClassify(t *testing.T) {
	for _, test := range []struct {
		name        string
		tid, tgid   uint32
		flags       uint64
		leaderFlags uint64
		want        closeAction
	}{
		{"creator thread", 101, 100, 0, 0, closePublish},
		{"creator leader", 100, 100, 0, 0, closePublish},
		{"creator sibling", 102, 100, 0, 0, closePublish},
		{"exiting creator", 101, 100, 4, 0, closeAbort},
		{"exiting sibling", 102, 100, 4194308, 0, closeAbort},
		{"other flags", 102, 100, 4194304, 0, closePublish},
		{"exited leader", 102, 100, 0, 4, closePublish},
		{"foreign", 200, 200, 0, 0, closeIgnore},
		{"foreign exiting", 200, 200, 4, 0, closeIgnore},
	} {
		t.Run(test.name, func(t *testing.T) {
			proc := t.TempDir()
			writeCloseTask(t, proc, 100, 100, test.leaderFlags)
			writeCloseTask(t, proc, 101, 100, 0)
			owner, err := newCloseOwnerAt(proc, 101)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			writeCloseTask(t, proc, test.tid, test.tgid, test.flags)
			got, err := owner.checkClose(test.tid)
			if err != nil || got != test.want {
				t.Fatalf("checkClose = %v, %v; want %v", got, err, test.want)
			}
		})
	}
}

func TestCloseOwnerProcErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		file string
		data string
	}{
		{"missing status", "status", ""},
		{"missing stat", "stat", ""},
		{"malformed status", "status", "Tgid: nope\n"},
		{"malformed stat", "stat", "100 (task)"},
		{"oversized status", "status", "Tgid: 100\n" + strings.Repeat("x", 65536)},
		{"oversized stat", "stat", closeStatFixture(100, "task", 0) + strings.Repeat(" ", 65536)},
	} {
		t.Run(test.name, func(t *testing.T) {
			proc := t.TempDir()
			writeCloseTask(t, proc, 100, 100, 0)
			owner, err := newCloseOwnerAt(proc, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			dir := filepath.Join(proc, "100")
			if test.data == "" {
				if err := os.Remove(filepath.Join(dir, test.file)); err != nil {
					t.Fatal(err)
				}
			} else {
				writeCloseProc(t, dir, test.file, test.data)
			}
			if action, err := owner.checkClose(100); err == nil || action == closePublish {
				t.Fatalf("checkClose = %v, %v; want error", action, err)
			}
			if other, err := newCloseOwnerAt(proc, 100); err == nil {
				other.Close()
				t.Fatal("constructor accepted invalid proc data")
			}
		})
	}
	if owner, err := newCloseOwnerAt(t.TempDir(), 100); err == nil {
		owner.Close()
		t.Fatal("constructor accepted missing task")
	}
}

func TestCloseOwnerMissingTaskOrProcess(t *testing.T) {
	for _, remove := range []string{"100", "101"} {
		t.Run(remove, func(t *testing.T) {
			proc := t.TempDir()
			writeCloseTask(t, proc, 100, 100, 0)
			writeCloseTask(t, proc, 101, 100, 0)
			owner, err := newCloseOwnerAt(proc, 101)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if err := os.RemoveAll(filepath.Join(proc, remove)); err != nil {
				t.Fatal(err)
			}
			if action, err := owner.checkClose(101); err == nil || action == closePublish {
				t.Fatalf("missing proc = %v, %v; want error", action, err)
			}
			if other, err := newCloseOwnerAt(proc, 101); err == nil {
				other.Close()
				t.Fatal("constructor accepted missing proc directory")
			}
		})
	}
}

func TestCloseOwnerInaccessibleProc(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 000 files")
	}
	proc := t.TempDir()
	writeCloseTask(t, proc, 100, 100, 0)
	owner, err := newCloseOwnerAt(proc, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := os.Chmod(filepath.Join(proc, "100", "status"), 0); err != nil {
		t.Fatal(err)
	}
	if action, err := owner.checkClose(100); err == nil || action == closePublish {
		t.Fatalf("inaccessible proc = %v, %v; want error", action, err)
	}
	if other, err := newCloseOwnerAt(proc, 100); err == nil {
		other.Close()
		t.Fatal("constructor accepted inaccessible proc data")
	}
}

func TestCloseOwnerPIDReplacement(t *testing.T) {
	for _, reap := range []bool{false, true} {
		t.Run(fmt.Sprintf("reap=%t", reap), func(t *testing.T) {
			proc := t.TempDir()
			writeCloseTask(t, proc, 100, 100, 0)
			owner, err := newCloseOwnerAt(proc, 100)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			old := filepath.Join(proc, "old")
			if err := os.Rename(filepath.Join(proc, "100"), old); err != nil {
				t.Fatal(err)
			}
			if reap {
				if err := os.RemoveAll(old); err != nil {
					t.Fatal(err)
				}
			}
			writeCloseTask(t, proc, 100, 100, 0)
			action, err := owner.checkClose(100)
			if err != nil || action != closeIgnore {
				t.Fatalf("reused PID = %v, %v; want ignore", action, err)
			}
		})
	}
}

func TestCloseOwnerLiveThreads(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint32(unix.Gettid())
	owner, err := newCloseOwner(tid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if action, err := owner.checkClose(tid); err != nil || action != closePublish {
		t.Fatalf("creator = %v, %v", action, err)
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		other := uint32(unix.Gettid())
		if other == tid {
			result <- fmt.Errorf("test did not use a separate OS thread")
			return
		}
		if action, err := owner.checkClose(other); err != nil || action != closePublish {
			result <- fmt.Errorf("sibling = %v, %v", action, err)
			return
		}
		threadOwner, err := newCloseOwner(other)
		if err == nil {
			defer threadOwner.Close()
			if action, checkErr := threadOwner.checkClose(tid); checkErr != nil || action != closePublish {
				err = fmt.Errorf("thread creator = %v, %v", action, checkErr)
			}
		}
		result <- err
	}()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pid := uint32(cmd.Process.Pid)
	childOwner, err := newCloseOwner(pid)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(err)
	}
	defer childOwner.Close()
	if action, err := owner.checkClose(pid); err != nil || action != closeIgnore {
		t.Errorf("foreign child = %v, %v", action, err)
	}
	if action, err := childOwner.checkClose(pid); err != nil || action != closePublish {
		t.Errorf("live child = %v, %v", action, err)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if action, err := owner.checkClose(pid); err == nil || action == closePublish {
		t.Errorf("reaped child = %v, %v; want error", action, err)
	}
	if action, err := childOwner.checkClose(pid); err == nil || action == closePublish {
		t.Errorf("reaped creator = %v, %v; want error", action, err)
	}
	owner.Close()
	owner.Close()
	if action, err := owner.checkClose(tid); err == nil || action == closePublish {
		t.Errorf("closed owner = %v, %v; want error", action, err)
	}
}
