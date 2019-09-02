(in-package :tls)

(defvar *client-connections*)
(defvar *dispatchers* '())

(defun client-dispatch-loop (dispatcher)
  (sb-sys:without-interrupts
    (unwind-protect
	 (sb-sys:with-local-interrupts
	   (with-dispatcher (dispatcher)
	     (loop
		do
		  (let ((events (wait-for-events)))
		    (format t "dispatching events: ~a~%" events)
		    (dispatch-events events)))))
      (format t "exiting thread ~a~%" sb-thread:*current-thread*)
      (format t "closing dispatcher ~a~%" dispatcher)
      (close-dispatcher dispatcher)
      (labels
	  ((get-key (x)
	     (reactor-handle
	      (dispatcher-reactor (car x)))))
	(remove dispatcher *dispatchers* :test #'= :key #'get-key)))))

(defun stop-dispatch-threads ()
  (loop for thread in *dispatchers*
     do (sb-thread:terminate-thread (cdr thread)))
  (setf *dispatchers* nil))

(defun start-client-loop ()
  (let ((disp (make-dispatcher)))
    (push
     (cons
      disp
      (sb-thread:make-thread
       #'client-dispatch-loop
       :name "CLIENT-DISPATCH"
       :arguments (list disp)))
     *dispatchers*)))

(defun client-socket-disconnected (ctx event)
  (declare (ignorable ctx event))
  (let ((socket (context-socket ctx)))
    (format t "disconnecting socket ~a~%" socket)
    (rem-socket socket)
    (disconnect socket)))

(defun get-next-dispatcher ()
  (when *dispatchers*
    (let ((tail (last *dispatchers*)))
      (let ((hd (car *dispatchers*))
	    (rst (cdr *dispatchers*)))
	(rplaca *dispatchers* (car rst))
	(rplacd *dispatchers* (cdr rst))
	(rplaca tail hd))))
  (car *dispatchers*))

(defun client-connect (host port)
  (let ((socket (make-tcp-socket t)))
    (let ((dispatcher (get-next-dispatcher)))
      (unless dispatcher
	(error "no dispatcher available"))

      (handler-case
	  (connect socket (get-host-addr host) port)
	(operation-in-progress ()
	  (format t "connecting...~%")))

      (with-dispatcher ((car dispatcher))
	(on-write socket #'client-socket-connected)
	(on-disconnect socket #'client-socket-disconnected))))
  (values))


(defun client-socket-connected (ctx event)
  (let ((socket (context-socket ctx)))
    (let ((conn (make-tls-connection socket :CLIENT-HELLO)))
      ;; associate connection data with the socket
      (setf (context-data ctx) conn)
      ;; push client hello packet onto the transmit queue
      (send-client-hello conn)
      ;; enable write notifications via tls-client-tx handler
      (on-write socket #'tls-tx))))

(defun send-client-hello (tls)
  (let ((hello (make-instance 'client-hello)))
    (setf
     (handshake-type hello) +CLIENT-HELLO+
     (random-bytes hello) (ironclad:random-data 32)
     (session-id hello) (list)
     (ciphers hello) (list
		      +TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384+
		      +TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256+)
     (compression hello) (list 0)
     (extensions hello) (list
			 (make-instance 'client-supported-versions
					:size (+ 1 (* 2 2))
					:extension-type +SUPPORTED-VERSIONS+
					:versions (list +TLS-1.3+ +TLS-1.2+))
			 (make-instance 'supported-groups
					:size (+ 2 (* 2 1))
					:named-groups (list +x25519+)
					:extension-type +SUPPORTED-GROUPS+)
			 (make-instance 'ec-point-formats
					:point-formats '(0)
					:size 2
					:extension-type +ec-point-formats+)
			 (make-instance 'signature-schemes
					:size (+ 2 (* 1 2))
					:extension-type +signature-algorithms+
					:signature-schemes
					(list +rsa-pss-rsae-sha384+))))

    (setf
     (size hello)
     (+ 2 32 1 (length (session-id hello))
	2 (* 2 (length (ciphers hello)))
	1 (length (compression hello))
	2 (reduce #'+ (mapcar #'tls-extension-size (extensions hello)))))

    (let ((record (make-instance 'tls-record
				 :size (tls-size hello)
				 :protocol-version +TLS-1.2+
				 :content-type +RECORD-HANDSHAKE+)))
      (write-value (type-of record) (tx-stream tls) record)
      (write-value (type-of hello) (tx-stream tls) hello))))

(defun get-version (hello)
  (loop for ext in (extensions hello)
     when (= (extension-type ext) +supported-versions+)
     do
       (when (find +TLS-1.3+ (versions ext))
	 (return-from get-version +TLS-1.3+)))
  (protocol-version hello))
