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
	 (*mode* :SERVER)
	 (*version*))
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
		   (transfer-rx-record tls hdr))

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
	      (format t "record size: ~a~%" (size hdr))
	      (let ((rectyp (get-record-content-type hdr))
		    (msg nil))
		(when (eq (type-of tls) 'tls-connection)
		  (setf msg (read-value rectyp (tls-rx-stream tls)))
		  (let* ((ver (get-version msg)))
		    (cond
		      ((= ver +TLS-1.2+)
		       (change-class tls 'tls12-connection)
		       (setf *version* +TLS-1.2+))
		      ((= ver +TLS-1.3+)
		       (change-class tls 'tls13-connection)
		       (setf *version* +TLS-1.3+))
		      (t (on-write (socket tls) #'send-protocol-alert tls)
			 (del-read (socket tls))
			 (return-from tls-client-rx)))))

		(cond
		  ((eq rectyp 'application-data)
		   (format t "encrypted packet~%")
		   (let ((msg (decrypt-record tls hdr)))
		     (client-process-record tls msg)))
		  (t
		   (cond
		     ((not (null msg)) (client-process-record tls msg))
		     (t
		      (format t "will read ~a packet~%" rectyp)
		      (let ((msg (read-value rectyp (tls-rx-stream tls))))
			(format t "unencrypted packet~%")
			(client-process-record tls msg)))))))
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

(defgeneric make-client-finished-msg (tls))
(defmethod make-client-finished-msg ((tls tls13-connection))
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

(defmethod make-client-finished-msg ((tls tls12-connection))
  (make-instance
   'finished
   :size (hash-len :sha384)
   :handshake-type +FINISHED+
   :data (make-array (hash-len :sha384) :element-type '(unsigned-byte 8) :initial-element 0)))

(defmethod send-client-finished-msg ((tls tls13-connection) finished-msg)
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

(defmethod send-client-finished-msg ((tls tls12-connection) finished-msg)
  (let* ((nonce (get-out-nonce! tls))
	 (key (my-key tls))
	 (iv (my-iv tls))
	 (aead (make-aead-aes256-gcm key iv nonce)))
    (labels ((write-to-seq (msg)
	       (alien-ring::with-output-to-byte-sequence (out (size finished-msg))
		 (write-value (type-of msg) out msg))))
      (let* ((ciphertext (ironclad:encrypt-message aead (write-to-seq finished-msg)))
	     (rec (make-instance 'tls-record :size (+ 16 (length ciphertext))
				:content-type +RECORD-APPLICATION-DATA+)))
	(write-value 'tls-record (tx-stream tls) rec)
	(write-value 'raw-bytes (tx-stream tls) nonce :size (length nonce))
	(write-sequence ciphertext (tx-stream tls))))

    (on-write (socket tls) #'tls-tx)
    (setf (state tls) :NEGOTIATED)))


(defgeneric client-process-record (tls msg))

(defmethod client-process-record ((tls tls12-connection) msg)
  (format t "tls 1.2 handler ~a~%" (type-of tls))
  (etypecase msg
    (server-hello
     (write-value 'server-hello (digest-stream tls) msg)
     (setf (server-random tls) (random-bytes msg)))

    (alert
     (format t "alert arrived: ~a:~a~%"
	     (level msg) (description msg)))

    (change-cipher-spec
     (write-value 'change-cipher-spec (digest-stream tls) msg))

    (tls12-certificate
     (write-value 'tls12-certificate (digest-stream tls) msg))

    (server-key-exchange-ecdh
     (write-value 'server-key-exchange-ecdh (digest-stream tls) msg)

     (setf (peer-key tls)
	   (ironclad:make-public-key
	    :curve25519 :y
	    (make-array (length (point (point (params msg))))
			:element-type '(unsigned-byte 8)
			:initial-contents (point (point (params msg)))))))

    (server-hello-done
     (write-value 'server-hello-done (digest-stream tls) msg)

     ;; compute tls 1.2 premaster secret
     (setf (shared-secret tls) (compute-dh-shared-secret tls))

     ;; compute keys
     (let* ((cr (client-random tls))
	    (sr (server-random tls))
	    (premaster (shared-secret tls))
	    (master (tls12-key-schedule premaster cr sr)))

       (format t "master key length: ~a~%" (length master))
       (multiple-value-bind (my-mac peer-mac my-key peer-key my-iv peer-iv)
	   (tls12-final-key master sr cr)
	 (setf (my-mac-key tls) my-mac
	       (peer-mac-key tls) peer-mac
	       (my-key tls) my-key
	       (peer-key tls) peer-key
	       (my-iv tls) my-iv
	       (peer-iv tls) peer-iv)

	 (format t "type of my key ~a~%" (type-of (my-key tls)))))

     ;; add client key exchange message to the transmit queue
     (generate-keys tls :curve25519)
     (let ((kex (make-client-key-exchange
		 (map 'list #'identity
		      (ironclad:curve25519-key-y (public-key tls))))))
       ;; update the digest
       (write-value 'client-key-exchange (digest-stream tls) kex)

       ;; queue up key exchange record header
       (write-value 'tls-record (tx-stream tls)
		    (make-instance
		     'tls-record :size 37
		     :content-type +RECORD-HANDSHAKE+))

       ;; queue up key exchange
       (write-value 'client-key-exchange (tx-stream tls) kex)

       ;; queue up record header for change cipher spec
       (write-value 'tls-record (tx-stream tls)
		    (make-instance 'tls-record :size 1
				   :content-type +RECORD-CHANGE-CIPHER-SPEC+))
       ;; queue up change cipher spec
       (write-value 'u8 (tx-stream tls) 1))

     (send-client-finished-msg
      tls (make-client-finished-msg tls))
     (on-write (socket tls) #'tls-tx))

    (t
     #+off(when (plusp (stream-size (rx-data-stream tls)))
       (when (read-fn tls)
	 (funcall (read-fn tls)
		  (data tls)
		  (stream-size (rx-data-stream tls))))))))

(defmethod client-process-record ((tls tls13-connection) msg)
  (etypecase msg
    (server-hello
     ;; find the key share extension in the hello msg
     (loop for ext in (extensions msg)
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
     (write-value (type-of msg) (digest-stream tls) msg)
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
     (setf (state tls) :SERVER-FINISHED))

    (alert
     (format t "alert arrived: ~a:~a~%"
	     (level msg) (description msg)))

    (change-cipher-spec
     (format t "cipher: ~a~%" (cipher msg)))

    (encrypted-extensions
     (write-value 'encrypted-extensions (digest-stream tls) msg))

    (certificate
     (write-value 'certificate (digest-stream tls) msg))

    (certificate-verify
     (write-value 'certificate-verify (digest-stream tls) msg))

    (finished
     (write-value 'finished (digest-stream tls) msg)

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
	     (my-app-iv tls) civ)))

    (t
     (when (plusp (stream-size (rx-data-stream tls)))
       (when (read-fn tls)
	 (funcall (read-fn tls)
		  (data tls)
		  (stream-size (rx-data-stream tls))))))))

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
					:size (+ 2 (* 2 2))
					:extension-type +signature-algorithms+
					:signature-schemes
					(list
					 +rsa-pss-rsae-sha384+
					 +rsa-pkcs1-sha384+))
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

      (setf (client-random tls) (random-bytes hello))

      ;; update digest stream
      (write-value (type-of hello) (digest-stream tls) hello)
      (on-read (socket tls) #'tls-client-rx))))

(defun get-version (hello)
  (format t "get version from ~a packet~%" (type-of hello))
  (when (or (typep hello 'server-hello)
	    (typep hello 'client-hello))
    (loop for ext in (extensions hello)
       when (= (extension-type ext) +supported-versions+)
       do
	 (etypecase hello
	   (server-hello
	    (return-from get-version (version ext)))
	   (client-hello
	    (when (find +TLS-1.3+ (versions ext))
	      (return-from get-version +TLS-1.3+)))))
    (protocol-version hello)))
