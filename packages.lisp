(defpackage tls
  (:use :cl)
  (:import-from :alien-ring
		:make-ring-buffer
		:ring-buffer-write-byte
		:ring-buffer-read-byte
		:ring-buffer-read-byte-sequence
		:ring-buffer-write-byte-sequence
		:stream-peek-byte)
  (:export
   :make-tls-context
   :load-private-key-der
   :tls-fd))
