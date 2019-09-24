(defpackage tls
  (:use :cl)
  (:import-from :alien-ring
		:make-ring-buffer
		:ring-buffer-write-byte
		:ring-buffer-read-byte
		:ring-buffer-read-byte-sequence
		:ring-buffer-write-byte-sequence
		:make-binary-ring-stream
		:stream-space-available
		:stream-peek-byte
		:stream-buffer
		:stream-size
		:with-output-to-byte-sequence)

  (:import-from :socket
		:set-non-blocking
		:operation-interrupted
		:operation-would-block
		:operation-in-progress
		:socket-eof
		:make-tcp-listen-socket
		:make-tcp-socket
		:connect
		:disconnect
		:get-host-addr)

  (:import-from :reactor
		:del-write
		:del-read
		:rem-handle
		:on-read
		:on-write
		:on-disconnect
		:context-data
		:context-handle
		:wait-for-events
		:dispatch-events
		:with-dispatcher
		:make-dispatcher
		:close-dispatcher
		:dispatcher-reactor
		:socket-context
		:make-context
		:reactor-handle
		:handle-key)

  (:import-from :flexi-streams
		:with-input-from-sequence)

  (:import-from :cl-speedy-queue
		:make-queue
		:dequeue
		:enqueue
		:queue-peek
		:queue-count
		:queue-empty-p
		:queue-full-p)
  (:export
   :make-tls-context
   :load-private-key-der
   :tls-fd
   :tls-connection
   :tls12-connection
   :tls13-connection
   :data
   :socket
   :start-server
   :tls-read
   :tls-write
   :tls-close))
