(in-package :tls)

(defvar *client-connections*)
(defvar *dispatch-thread*)

(defun make-client-dispatcher ()
  (unless (and (boundp '*dispatcher*) *dispatcher*)
    (setf *dispatcher* (make-dispatcher))))

(defun client-dispatch-loop (dispatcher)
  (with-dispatcher (dispatcher)
    (loop
       do
	 (let ((events (wait-for-events)))
	   (format t "dispatching events: ~a~%" events)
	   (dispatch-events events)))))

(defun start-client-loop (dispatcher)
  (unless (and (boundp '*dispatch-thread*) *dispatch-thread*)
    (setf *dispatch-thread*
	  (sb-thread:make-thread
	   #'client-dispatch-loop :name "CLIENT-DISPATCH-LOOP"
	   :arguments (list dispatcher)))))

(defun client-socket-connected (ctx event)
  (declare (ignorable ctx event))
  (with-dispatcher (*dispatcher*)
    (let ((socket (context-socket ctx)))
      ;; TODO: here, we can call the callback
      (format t "client socket connected~%")
      (del-write socket))))

(defun client-socket-disconnected (ctx event)
  (declare (ignorable ctx event))
  (with-dispatcher (*dispatcher*)
    (let ((socket (context-socket ctx)))
      (format t "disconnecting socket ~a~%" socket)
      (rem-socket socket)
      (disconnect socket))))

(defun client-connect (host port)
  (let ((socket (make-tcp-socket t)))
    (handler-case
	(connect socket (get-host-addr host) port)
      (operation-in-progress ()
	(format t "connecting...~%")))

    (with-dispatcher (*dispatcher*)
      (on-write socket #'client-socket-connected)
      (on-read socket #'client-socket-connected)
      (on-disconnect socket #'client-socket-disconnected)))
  (values))
