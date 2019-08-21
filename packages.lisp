(defpackage tls
  (:use :cl)
  (:import-from :alien-ring
		:make-ring-buffer
		:ring-buffer-write-byte
		:ring-buffer-read-byte
		:ring-buffer-read-byte-sequence
		:ring-buffer-write-byte-sequence)
  (:export
   :make-tls-context
   :tls-fd))
