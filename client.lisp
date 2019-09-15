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
    (let ((conn (make-tls-connection socket :CLIENT-HELLO
				     ctx nil nil nil nil nil)))
      ;; associate connection data with the socket
      (setf (context-data ctx) conn)
      ;; push client hello packet onto the transmit queue
      (send-client-hello conn)
      (setf (state (context-data ctx)) :SERVER-HELLO)
      ;; enable write notifications via tls-client-tx handler
      (on-write socket #'tls-tx))))

(defun tls-client-rx (ctx event)
  "Top level client read notification handler to plug into the reactor."
  (declare (ignore event))
  (let* ((sd (context-socket ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (*mode* :CLIENT))
    (let ((tls (context-data ctx)))
      (handler-case
       (with-slots (rx rxbuf) tls
	 ;; read pending bytes from the socket into the tls buffer
	 (rx-into-buffer sd (stream-buffer rx) nbytes)

	 ;; read the record header (5 bytes) from the rx queue
	 ;; and push it to the records list.
	 (loop
	    while (>= (stream-size rx) 5)
	    do
	      (let ((hdr (read-value 'tls-record rx)))
		;; sanity check the record header and only allow
		;; TLS-1.2 because the field is obsoleted. anything
		;; less than TLS 1.2 is dropped
		(unless (and
			 (valid-content-p (content-type hdr))
			 (valid-version-p (protocol-version hdr)))

		  ;; stop reading from this socket
		  (del-read (socket tls))

		  ;; on next write, we send the protocol alert
		  (on-write sd #'send-protocol-alert tls)
		  (return-from tls-client-rx))

		;; deserialize the header
		(setf (tls-records tls)
		      (append (tls-records tls) (list hdr)))

		(cond
		  ;; check if the ring buffer has enough data for a
		  ;; complete record and if so, process it immediately
		  ((>= (stream-size rx) (size hdr))
		   ;; here, we need to read the packet bytes and transfer
		   ;; them into another buffer that is aggregating
		   ;; fragments into complete higher level packets.  we
		   ;; can't read the packet yet because it could have
		   ;; been fragmented across many records

		   ;; transfer the record bytes from the RX stream into
		   ;; TLS-RX de-encapsulating from the record layer
		   (let ((*mode* :SERVER))
		     (transfer-rx-record tls hdr)))

		  ;; if not enough data present, we need to wait for
		  ;; another read event to continue filling the record
		  ;; in such case we terminate the loop and start
		  ;; processing completed packets
		  ((< (stream-size rx) (size hdr)) (loop-finish)))))


	 ;; process de-encapsulated records until we
	 ;; reach the end of the list
	 (loop
	    for hdr in (tls-records tls)
	    do
	      (format t "type=~a, version=~2,'0x, len=~a~%"
		      (content-type hdr)
		      (protocol-version hdr)
		      (size hdr))
	      (client-process-record tls)
	      (pop (tls-records tls))

	    ;; are we done with the current record?
	      (format t "stream size after processing ~a~%"
		      (stream-size (tls-rx-stream tls)))))

	(alert-arrived (a)
	  (with-slots (alert) a
	    (format t "alert arrived: ~a:~a~%" (level alert) (description alert))
	    (on-write (socket tls) #'send-close-notify)))

	(socket-eof ()
	  (format t "disconnecting on eof~%")
	  (rem-socket (socket tls))
	  (disconnect (socket tls)))

	(no-common-cipher ()
	  (del-read (socket tls))
	  (on-write (socket tls) #'send-insufficient-security-alert))))))

(defun make-client-finished-msg (tls)
  (let* ((finished-key (make-finished-key (my-handshake-secret tls) :sha384))
	 (finished-hash (ironclad:produce-digest (digest-stream tls)))
	 (finished-data (ironclad:produce-mac
			 (ironclad:update-hmac
			  (ironclad:make-hmac finished-key :sha384)
			  finished-hash))))
    (make-instance
     'finished
     :size (hash-len :sha384)
     :handshake-type +FINISHED+
     :data finished-data)))

(defun send-client-finished-msg (tls finished-msg)
  (let* ((aead (make-aead-aes256-gcm (my-handshake-key tls)
				     (my-handshake-iv tls)
				     (get-out-nonce! tls)))
	 (ciphertext (encrypt-messages
		      aead
		      (list finished-msg) +RECORD-HANDSHAKE+))
	 (rec (make-instance 'tls-record :size (+ 16 (length ciphertext))
			     :content-type +RECORD-APPLICATION-DATA+)))
    (write-value 'tls-record (tx-stream tls) rec)
    (write-sequence ciphertext (tx-stream tls))
    (write-sequence (ironclad:produce-tag aead) (tx-stream tls))
    (on-write (socket tls) #'tls-tx)
    (reset-nonces! tls)
    (setf (state tls) :NEGOTIATED)))

(defun client-process-record (tls)
  (with-slots (tlsrx state records) tls
    (let* ((hdr (first records))
	   (content-type (get-record-content-type hdr)))
      (format t "content type = ~a~%" content-type)
      (case state
	(:SERVER-HELLO
	 (let ((server-hello (let ((*mode* :SERVER))
			       (read-value content-type tlsrx))))

	   (when (/= (get-version server-hello) +TLS-1.3+)
	     (on-write (socket tls) #'send-protocol-alert tls)
	     (del-read (socket tls))
	     (error "wrong protocol version"))

	   ;; find the key share extension
	   (loop for ext in (extensions server-hello)
	      when (typep ext 'server-hello-key-share)
	      do
		(let ((keyshare (key ext)))
		  (setf (peer-key tls)
			(ironclad:make-public-key
			 :curve25519 :y (key-exchange keyshare)))

		;; diffie-hellman key exchange
		(setf (shared-secret tls)
		      (compute-dh-shared-secret tls))))

	   ;; update the handshake digest stream
	   (write-value (type-of server-hello) (digest-stream tls) server-hello)

	   ;; compute handshake keys so we can proceed decoding packets
	   (multiple-value-bind (hs-secret ss skey siv cs ckey civ)
	       (handshake-key-schedule
		(shared-secret tls)
		(ironclad:produce-digest (digest-stream tls))
		:hash :sha384 :cipher :aes256)
	     (setf (handshake-secret tls) hs-secret
		   (peer-handshake-secret tls) ss
		   (peer-handshake-key tls) skey
		   (peer-handshake-iv tls) siv
		   (my-handshake-secret tls) cs
		   (my-handshake-key tls) ckey
		   (my-handshake-iv tls) civ))
	   (setf (state tls) :SERVER-FINISHED)))

	(:SERVER-FINISHED
	 (cond
	   ((= (content-type hdr) +RECORD-CHANGE-CIPHER-SPEC+)
	    ;; TODO: do we need to do anything with this message?
	    (read-value content-type tlsrx))

	   ((= (content-type hdr) +RECORD-APPLICATION-DATA+)
	    (let ((record (decrypt-record tls hdr)))
	      (format t "record type=~a~%" (type-of record))
	      (etypecase record
		(alert
		 (format t "alert arrived: ~a:~a~%"
			 (level record) (description record)))

		(change-cipher-spec
		 (format t "ignoring cipher change packet~%"))

		(encrypted-extensions
		 (write-value 'encrypted-extensions (digest-stream tls) record))

		(certificate
		 (write-value 'certificate (digest-stream tls) record))

		(certificate-verify
		 (write-value 'certificate-verify (digest-stream tls) record))

		(finished
		 (write-value 'finished (digest-stream tls) record)

		 ;; create and send client finished message
		 (send-client-finished-msg tls (make-client-finished-msg tls))

		 ;; switch the keys
		 (multiple-value-bind (ss sk siv cs ck civ)
		     (application-key-schedule
		      (handshake-secret tls)
		      (ironclad:produce-digest (digest-stream tls)))
		   (setf (peer-app-secret tls) ss
			 (peer-app-key tls) sk
			 (peer-app-iv tls) siv
			 (my-app-secret tls) cs
			 (my-app-key tls) ck
			 (my-app-iv tls) civ))))))))

	(:NEGOTIATED
	 (decrypt-record tls (first (tls-records tls)))

	 (when (plusp (stream-size (rx-data-stream tls)))
	   (funcall (read-fn tls)
		    (data tls)
		    (stream-size (rx-data-stream tls)))))))))

(defun send-client-hello (tls)
  (let ((hello (make-instance 'client-hello)))
    (generate-keys tls :curve25519)

    (setf
     (handshake-type hello) +CLIENT-HELLO+
     (random-bytes hello) (ironclad:random-data 32)
     (session-id hello) (list)
     (ciphers hello) (list
		      +TLS-AES-256-GCM-SHA384+
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
					(list +rsa-pss-rsae-sha384+))
			 (make-client-keyshare
			  +x25519+
			  (ironclad:curve25519-key-y (public-key tls)))))

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
      (write-value (type-of hello) (tx-stream tls) hello)

      ;; update digest stream
      (write-value (type-of hello) (digest-stream tls) hello)
      (on-read (socket tls) #'tls-client-rx))))

(defun get-version (hello)
  (loop for ext in (extensions hello)
     when (= (extension-type ext) +supported-versions+)
     do
       (etypecase hello
	 (server-hello
	  (return-from get-version (version ext)))
	 (client-hello
	  (when (find +TLS-1.3+ (versions ext))
	    (return-from get-version +TLS-1.3+)))))
  (protocol-version hello))
