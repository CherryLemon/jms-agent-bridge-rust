# Terminal input and foreground ownership

Terminal EOF reports an SSH send failure with the result ID selected for the write. This error does not determine the command's execution or completion state. Read the selected result for that evidence; do not automatically replay input. Success indicates that the transport accepted the EOF send, not that a particular process consumed it.

The interactive protocol uses one persistent SSH channel for both shell command packets and unframed input. Signals and EOF also address that channel. Locking local admission and checking a result ID cannot prove remote foreground ownership: the old command may already have exited while its completion marker is still in transit.

An explicit single-use command/session mode could dedicate a channel to one command and never reuse that channel after input. This is the simpler isolation boundary but sacrifices persistent cwd, environment, and REPL state. For reusable shells, a remote input protocol would need command-addressed stdin endpoints, explicit EOF and delivery receipts, and command-scoped process groups for signals. It must reject an expired command identity remotely, preserve existing shell behavior, and handle commands that exit while an input operation is underway. Until such a contract exists, legacy unscoped terminal input remains unchanged.
