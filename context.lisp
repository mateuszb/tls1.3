(in-package :tls)

(defparameter +TLS-RING-BUFFER-SIZE+ (* 64 16384))

(defclass tls-context ()
  ((tx :initform (make-ring-buffer +TLS-RING-BUFFER-SIZE+) :reader tls-tx-ring)
   (rx :initform (make-ring-buffer +TLS-RING-BUFFER-SIZE+) :reader tls-rx-ring)
   (fd :initform -1 :initarg :fd :reader tls-fd)
   (state :initform -1)))

(defun make-tls-context ()
  (make-instance 'tls-context))
