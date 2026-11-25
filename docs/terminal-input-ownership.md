# Terminal input and foreground ownership

Terminal EOF reports an SSH send failure with the result ID selected for the write. This error does not determine the command's execution or completion state. Read the selected result for that evidence; do not automatically replay input. Success indicates that the transport accepted the EOF send, not that a particular process consumed it.

The interactive protocol uses one persistent SSH channel for both shell command packets and unframed input. Signals and EOF also address that channel. Locking local admission and checking a result ID cannot prove remote foreground ownership: the old command may already have exited while its completion marker is still in transit.

Both the public and legacy write interfaces reject an `expected_result_id` guard for stdin, signals, or EOF before dispatching the write. The guard is available for `terminal.close`. An unscoped write retains its existing channel-level behavior; callers that require command ownership should not remove the guard and retry.

An explicit single-use command/session mode could dedicate a channel to one command and never reuse that channel after input. This is the simpler isolation boundary but sacrifices persistent cwd, environment, and REPL state. For reusable shells, a remote input protocol would need command-addressed stdin endpoints, explicit EOF and delivery receipts, and command-scoped process groups for signals. It must reject an expired command identity remotely, preserve existing shell behavior, and handle commands that exit while an input operation is underway. Until such a contract exists, legacy unscoped terminal input remains unchanged.


A command-scoped read resolves its immutable result ID even while the shell
has a successor command. Each caller can paginate the retained stdout and
stderr independently; its explicit source-byte cursor never changes the
current command's implicit read position. Once normal result cleanup expires
the selected command, the read reports an error. It never returns a page
from the successor.


## Reconciling terminal open

Supply `terminal(action="open", target=…, options={"request_id":"…"})` before opening a shell. The legacy `terminal_open` operation accepts the same ID in its `arguments`. If the response is lost, use `meta(ref="request:…")` or retry the same open with the same arguments and ID. An `opening` receipt has no usable handle yet. After a bridge restart, a saved handle can report `lost`; use a fresh ID only when you intend to open a separate shell.
