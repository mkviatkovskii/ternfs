# Ternfuse file publication

Without `-close-tracker-object`, ternfuse uses Linux procfs to apply the
creator-process policy described in [kernel file tracking](kmod-file-tracking.md).
The daemon must be able to inspect callers in the same PID namespace.
Creation rejects a procfs namespace mismatch or missing NStgid information.

Creation records the creating process, normalizing its thread ID to TGID.
An open proc directory pins that identity across PID reuse. On Flush:

- A different process cannot finalize the file.
- A caller with PF_EXITING set aborts the creator's unfinished file.
- A live caller in the creating process publishes synchronously.
- Unreadable or inconsistent process information returns EIO without publication.

PF_EXITING is set during Linux do_exit before descriptor cleanup. It is a
userspace exit indicator, not access to the kernel client's mm pointer.

Publication remains in Flush because errors from Release are ignored by FUSE.
Release discards any remaining transient buffer and closes the identity handle;
it never publishes. Symlinks publish directly when their creation completes.

As in the kernel client, explicit close by the creator finalizes a file even
when duplicated descriptors remain. This is not general last-reference
publication. Published files still reject append, overwrite, and truncation.

Supplying `-close-tracker-object` retains the existing BPF tracking mode and
its privilege requirements.
