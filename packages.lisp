(defpackage tls
  (:use :cl)
  (:import-from :alien-ring
		:make-ring-buffer
		:ring-buffer-write-byte
		:ring-buffer-read-byte
		:ring-buffer-read-byte-sequence
		:ring-buffer-write-byte-sequence
		:make-binary-ring-stream
		:stream-peek-byte
		:stream-buffer)
  (:import-from :socket
		:set-non-blocking
		:operation-interrupted
		:operation-would-block
		:operation-in-progress
		:make-tcp-listen-socket
		:make-tcp-socket
		:connect
		:disconnect
		:get-host-addr)
  (:import-from :reactor.dispatch
		:del-write
		:del-reado
		:rem-socket
		:on-read
		:on-write
		:on-disconnect
		:context-data
		:context-socket
		:wait-for-events
		:dispatch-events
		:with-dispatcher
		:make-dispatcher
		:*dispatcher*)
  (:export
   :make-tls-context
   :load-private-key-der
   :tls-fd))
