(in-package :tls)

(defvar *client-connections*)
(defvar *dispatchers* '())
(defvar *key-exchange*)

(defun client-dispatch-loop (dispatcher)
  (sb-sys:without-interrupts
    (unwind-protect
	 (sb-sys:with-local-interrupts
	   (with-dispatcher (dispatcher)
	     (loop
		do
		  (let ((events (wait-for-events)))
		    (dispatch-events events))))
	   )
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

(defun client-loop-running-p ()
  (not (null *dispatchers*)))

(defun client-socket-disconnected (ctx event)
  (declare (ignorable ctx event))
  (let ((socket (context-handle ctx)))
    (rem-handle socket)
    (disconnect socket)))

(defun get-next-dispatcher ()
  (if (client-loop-running-p)
      (let ((tail (last *dispatchers*)))
	(let ((hd (car *dispatchers*))
	      (rst (cdr *dispatchers*)))
	  (rplaca *dispatchers* (car rst))
	  (rplacd *dispatchers* (cdr rst))
	  (rplaca tail hd)))
      (start-client-loop))
  (car *dispatchers*))

(defun client-connect (host port &optional connect-fn read-fn write-fn disconnect-fn)
  (let ((socket (make-tcp-socket t)))
    (let ((dispatcher (get-next-dispatcher)))
      (unless dispatcher
	(error "no dispatcher available"))

      (handler-case
	  (connect socket (get-host-addr host) port)
	(operation-in-progress ()
	  (format t "connecting...~%")))

      (with-dispatcher ((car dispatcher))
	(on-write socket #'client-socket-connected
		  (list :host host
			:connector connect-fn
			:reader read-fn
			:writer write-fn
			:disconnector disconnect-fn))
	(on-disconnect socket #'client-socket-disconnected))))
  (values))

(defun client-socket-connected (ctx event)
  (declare (ignorable event))
  (let* ((socket (context-handle ctx))
	 (data (context-data ctx))
	 (host (getf data :host))
	 (readfn (getf data :reader))
	 (writefn (getf data :writer))
	 (connectfn (getf data :connector))
	 (disconnectfn (getf data :disconnector)))
    (let ((conn (make-tls-connection
		 host socket :CLIENT-HELLO
		 ctx connectfn readfn writefn nil disconnectfn)))
      ;; associate connection data with the socket
      (setf (context-data ctx) conn)
      ;; push client hello packet onto the transmit queue
      (send-client-hello (context-data ctx))
      (setf (state (context-data ctx)) :SERVER-HELLO)
      ;; enable write notifications via tls-client-tx handler
      (on-write socket #'tls-tx (context-data ctx)))))

(defun tls-client-rx (ctx event)
  "Top level client read notification handler to plug into the reactor."
  (declare (ignore event)
	   (optimize (debug 3) (speed 0)))
  (let* ((sd (context-handle ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (tls (context-data ctx))
	 (*mode* :SERVER)
	 (*version* (tls-version tls)))
    (with-slots (rx rxbuf version state records pending tlsrx socket) tls
      (handler-case
	  (progn
	    ;; read pending bytes from the socket into the tls buffer
	    (rx-into-buffer sd (stream-buffer rx) nbytes)

	    #+debug
	    (format t "stream size = ~a after attempting to read ~a bytes~%"
		    (stream-size rx) nbytes)

	    ;; when reading packets, we need to check two scenarios
	    ;; scenario 1: no partial record header is present
	    ;;      - we check if the stream has at least 5 bytes
	    ;;        and read the record header (5 bytes)
	    ;;      - we check if the record is complete and
	    ;;        transfer it between buffers if so.
	    ;;        otherwise we put the partial header on
	    ;;        the pending list
	    ;;
	    ;; scenario 2: there is a partial record header present
	    ;;      - we check if the new stream size is enough
	    ;;        to transfer the entire record. if we have
	    ;;        enough data we transfer the record and remove
	    ;;        partial record from the list
	    ;;
	    ;; invariant: there is at most one pending record header

	    ;; scenario 2
	    (when pending
	      (let ((hdr pending))
		(cond
		  ((>= (stream-size rx) (size hdr))
		   #+debug
		   (format t "completed pending record of size ~a~%" (size hdr))
		   (setf records (append records (list hdr)))
		   (transfer-rx-record tls hdr)
		   (setf pending nil))
		  (t
		   #+debug
		   (format t "not enough data to complete the pending record~%")
		   (return-from tls-client-rx)))))

	    ;; scenario 1
	    (loop
	       while (not pending)
	       while (>= (stream-size rx) 5)
	       do
		 (let ((hdr (read-value 'tls-record rx)))
		   #+debug
		   (format t "processing header of content type ~a and length ~a~%"
			   (content-type hdr) (size hdr))
		   ;; sanity check the record header and only allow
		   ;; certain versions in the version field
		   (unless (and
			    (valid-content-p (content-type hdr))
			    (valid-version-p (protocol-version hdr)))
		     ;; stop reading from this socket
		     (del-read socket)
		     ;; on next write, we send the protocol alert
		     (on-write sd #'send-protocol-alert tls)
		     (return-from tls-client-rx))

		   (cond
		     ;; check if the ring buffer has enough data for the processing
		     ;; of a complete record at the head of the pending list
		     ((>= (stream-size rx) (size hdr))

		      ;; append the header to the records list
		      (setf (tls-records tls) (append records (list hdr)))

		      ;; TODO: remove the header from the pending list if it was on one?
		      ;; TODO: this needs to be redesigned...

		      ;; here, we need to read the packet bytes and transfer
		      ;; them into another buffer that is aggregating
		      ;; fragments into complete higher level packets.  we
		      ;; can't read the packet yet because it could have
		      ;; been fragmented across many records

		      ;; transfer the record bytes from the RX stream into
		      ;; TLS-RX de-encapsulating from the record layer
		      #+debug
		      (format t "we have enough bytes to transfer record of ~a bytes~%"
			      (size hdr))
		      (transfer-rx-record tls hdr))

		     ;; if not enough data present, we need to wait for
		     ;; another read event to continue filling the record
		     ;; in such case we terminate the loop and start
		     ;; processing completed packets
		     ((< (stream-size rx) (size hdr))
		      #+debug
		      (format t "not enough bytes in the buffer for the record of ~a bytes~%"
			      (size hdr))
		      #+debug
		      (format t "buffer has ~a bytes of data~%" (stream-size rx))
		      (setf pending hdr)
		      (loop-finish)))))

	    ;; process de-encapsulated records until we
	    ;; reach the end of the list
	    (loop
	       for hdr in records
	       do
		 #+debug
		 (format t "record list=~a~%" records)
		 (let ((rectyp (get-record-content-type hdr))
		       (msg nil))
		   (when (eq (type-of tls) 'tls-connection)
		     (setf msg (read-value rectyp tlsrx))
		     (let* ((ver (get-version msg)))
		       #+debug
		       (format t "~a version = ~x~%" rectyp ver)
		       (cond
			 ((= ver +TLS-1.2+)
			  (setf (context-data ctx)
				(change-class tls 'tls12-connection)
				*version* +TLS-1.2+
				version +TLS-1.2+))

			 ((= ver +TLS-1.3+)
			  (setf (context-data ctx)
				(change-class tls 'tls13-connection)
				*version* +TLS-1.3+
				version +TLS-1.3+)

			  ;; remove all other keys different than curve 25519
			  (let ((pubkeys (cdar (delete-if-not
						(lambda (x) (eq x :curve25519))
						(pubkey tls) :key #'car)))
				(privkeys (cdar (delete-if-not
						 (lambda (x) (eq x :curve25519))
						 (privkey tls) :key #'car))))
			    (setf (slot-value tls 'pubkey) pubkeys)
			    (setf (slot-value tls 'seckey) privkeys)))

			 (t
			  (on-write socket #'send-protocol-alert tls)
			  (del-read socket)
			  (return-from tls-client-rx)))))

		   (cond
		     ((= *version* +TLS-1.3+)
		      (cond
			((eq rectyp 'application-data)
			 (let ((msg (decrypt-record tls hdr)))
			   (client-process-record tls msg)))
			(t
			 (cond
			   ((not (null msg)) (client-process-record tls msg))
			   (t
			    #+debug
			    (format t "will read ~a packet~%" rectyp)
			    (let ((msg (read-value rectyp tlsrx)))
			      #+debug
			      (format t "unencrypted packet~%")
			      (client-process-record tls msg)))))))

		     ((= *version* +TLS-1.2+)
		      (case (state tls)
			(:NEGOTIATED
			 (case rectyp
			   (change-cipher-spec
			    (read-value rectyp tlsrx))
			   (otherwise
			    (let ((msg (decrypt-record tls hdr)))
			      (client-process-record tls msg)))))
			(otherwise
			 (cond
			   ((not (null msg))
			    #+debug
			    (format t "processing ~a message~%" (type-of msg))
			    (client-process-record tls msg))
			   (t
			    (let ((msg (read-value rectyp tlsrx)))
			      (client-process-record tls msg))))))))
		   (pop records)
		   #+debug
		   (format t "pending record list after pop=~a~%" records)
		   #+debug
		   (format t "stream size after processing ~a~%"
			   (stream-size tlsrx)))))

	(alert-arrived (a)
	  (with-slots (alert) a
	    (format t "alert arrived: ~a:~a~%" (level alert) (description alert))
	    (on-write socket #'send-close-notify)))

	(socket-eof ()	  
	  (format t "disconnecting on eof~%")
	  (rem-handle socket)
	  (disconnect socket))

	(no-common-cipher ()
	  (del-read socket)
	  (on-write socket #'send-insufficient-security-alert))))))

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
  (let* ((digest (ironclad:produce-digest (digest-stream tls)))
	 (master (tls12-master-key (shared-secret tls) (client-random tls) (server-random tls)))
	 (finished (tls12-finished-hash master digest)))
    (make-instance
     'finished
     :size 12
     :handshake-type +FINISHED+
     :data (subseq finished 0 12))))

(defmethod send-client-finished-msg ((tls tls13-connection) finished-msg)
  (let* ((aead (make-aead-aes256-gcm (my-handshake-key tls)
				     (my-handshake-iv tls)
				     (get-out-nonce! tls)))
	 (ciphertext (encrypt-messages aead (list finished-msg) +RECORD-HANDSHAKE+))
	 (rec (make-instance 'tls-record :size (+ 16 (length ciphertext))
			     :content-type +RECORD-APPLICATION-DATA+)))
    (write-value 'tls-record (tx-stream tls) rec)
    (write-sequence ciphertext (tx-stream tls))
    (write-sequence (ironclad:produce-tag aead) (tx-stream tls))
    (on-write (socket tls) #'tls-tx)
    (reset-nonces! tls)
    (setf (state tls) :NEGOTIATED)))

(defun tls12-make-aead-data (seqnum type version length)
  (ironclad:hex-string-to-byte-array
   (format nil "~16,'0x~2,'0x~4,'0x~4,'0x" seqnum type version length)))

(defmethod send-client-finished-msg ((tls tls12-connection) finished-msg)
  (let* ((nonce (get-out-nonce! tls))
	 (key (my-key tls))
	 (nonce-iv (my-iv tls))
	 (explicit-iv (ironclad:random-data 8))
	 (iv (concatenate '(vector (unsigned-byte 8)) nonce-iv explicit-iv))
	 (aead (make-aead-aes256-gcm key iv 0)))
    (labels ((write-to-seq (msg)
	       (alien-ring::with-output-to-byte-sequence (out (+ 4 (size finished-msg)))
		 (write-value (type-of msg) out msg))))
      (let* ((plaintext (write-to-seq finished-msg))
	     (len (length plaintext))
	     (aead-data
	      (tls12-make-aead-data
	       nonce +RECORD-HANDSHAKE+
	       +TLS-1.2+ len))
	     (ciphertext (ironclad:encrypt-message aead plaintext :associated-data aead-data))
	     (rec (make-instance 'tls-record :size (+ 8 len 16)
				:content-type +RECORD-HANDSHAKE+)))
	(write-value 'tls-record (tx-stream tls) rec)
	(write-value 'raw-bytes (tx-stream tls) explicit-iv :size (length explicit-iv))
	(write-sequence ciphertext (tx-stream tls))
	(write-sequence (ironclad:produce-tag aead) (tx-stream tls))))

    (on-write (socket tls) #'tls-tx)
    (setf (state tls) :NEGOTIATED)))


(defun cipher->curve (cipher)
  (cond
    ((= cipher +TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384+) :secp256r1)
    ((= cipher +TLS-AES-256-GCM-SHA384+) :x25519)))

(defgeneric client-process-record (tls msg))

(defmethod client-process-record ((tls tls12-connection) msg)
  #+debug
  (format t "tls-1.2: message type ~a~%" (type-of msg))
  (etypecase msg
    (vector
     ;; notify the client if callback is present?
     (when (read-fn tls)
       (funcall (read-fn tls) tls msg)))

    (server-hello
     (setf (cipher tls) (selected-cipher msg))
     (write-value 'server-hello (digest-stream tls) msg)
     (setf (server-random tls) (random-bytes msg)))

    (alert
     (format t "alert arrived: ~a:~a~%" (level msg) (description msg)))

    (change-cipher-spec)

    (tls12-certificate
     (write-value 'tls12-certificate (digest-stream tls) msg))

    (server-key-exchange-ecdh
     (write-value 'server-key-exchange-ecdh (digest-stream tls) msg)

     (let ((ectype (curve-type (params (params msg)))))
       (cond
	 ((= ectype +named-curve+)
	  (let ((curve (ec-named-curve-symbol (named-curve (params (params msg))))))
	    (case curve
	      (:curve25519
	       (setf (tls-ec tls) :curve25519
		     (peer-key-exchange-key tls)
		     (make-curve25519-public-key
		      (point (point (params msg)))))
	       ;; remove all other keys from this field
	       (let ((pubkeys (pubkey tls))
		     (privkeys (privkey tls)))
		 (setf (pubkey tls)  (cdr (assoc :curve25519 pubkeys))
		       (privkey tls) (cdr (assoc :curve25519 privkeys)))))

	      (:secp256r1
	       (setf (tls-ec tls) :secp256r1
		     (peer-key-exchange-key tls)
		     (make-secp256r1-public-key
		      (make-array
		       64 :element-type '(unsigned-byte 8)
		       :initial-contents (cdr (point (point (params msg)))))))
	       (let ((pubkeys (cdar
			       (delete-if-not
				(lambda (x) (eq x :secp256r1)) (pubkey tls) :key #'car)))
		     (privkeys (cdar
				(delete-if-not
				 (lambda (x) (eq x :secp256r1)) (privkey tls) :key #'car))))
		 (setf (slot-value tls 'pubkey) pubkeys)
		 (setf (slot-value tls 'seckey) privkeys)))))))))

    (finished
     ;; TODO: call client callback here?
     (when (connect-fn tls)
       (funcall (connect-fn tls) tls)))

    (server-hello-done
     (write-value 'server-hello-done (digest-stream tls) msg)

     ;; add client key exchange message to the transmit queue
     (let ((kex (make-client-key-exchange (coerce (public-key-bytes (pubkey tls)) 'list))))
       ;; update the digest
       (write-value 'client-key-exchange (digest-stream tls) kex)

       ;; queue up key exchange record header
       (write-value 'tls-record (tx-stream tls)
		    (make-instance
		     'tls-record :size (+ 4 1 (length (pubkey kex)))
		     :content-type +RECORD-HANDSHAKE+))

       ;; queue up key exchange
       (write-value 'client-key-exchange (tx-stream tls) kex)

       ;; queue up record header for change cipher spec
       (let ((change-cipher
	      (make-instance 'tls-record :size 1
			     :content-type +RECORD-CHANGE-CIPHER-SPEC+)))
	 ;; queue up change cipher spec
	 (write-value 'tls-record (tx-stream tls) change-cipher)
	 (write-value 'u8 (tx-stream tls) 1)))

     ;; compute tls 1.2 premaster secret
     (setf (shared-secret tls) (compute-dh-shared-secret tls))

     ;; compute keys
     (let* ((cr (client-random tls))
	    (sr (server-random tls))
	    (premaster (shared-secret tls))
	    (master (tls12-master-key premaster cr sr)))

       (multiple-value-bind (my-key peer-key my-iv peer-iv)
	   (tls12-key-schedule
	    (tls12-final-key master sr cr))
	 (setf (my-key tls) my-key
	       (peer-key tls) peer-key
	       (my-iv tls) my-iv
	       (peer-iv tls) peer-iv)))

     (send-client-finished-msg tls (make-client-finished-msg tls))

     (on-write (socket tls) #'tls-tx))))

(defmethod client-process-record ((tls tls13-connection) msg)
  (etypecase msg
    (server-hello
     (setf (cipher tls) (selected-cipher msg))

     ;; find the key share extension in the hello msg
     (loop for ext in (extensions msg)
	when (typep ext 'server-hello-key-share)
	do
	  (let ((keyshare (key ext)))
	    (setf (peer-key-exchange-key tls)
		  (make-curve25519-public-key (key-exchange keyshare)))

	    ;; diffie-hellman key exchange
	    (setf (shared-secret tls)
		  (compute-dh-shared-secret tls))))

     ;; update the handshake digest stream
     (write-value 'server-hello (digest-stream tls) msg)

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

    (change-cipher-spec)

    (encrypted-extensions
     (write-value 'encrypted-extensions (digest-stream tls) msg))

    (certificate
     (write-value 'certificate (digest-stream tls) msg))

    (certificate-verify
     (write-value 'certificate-verify (digest-stream tls) msg))

    (finished
     (write-value 'finished (digest-stream tls) msg)


     ;; create and send client finished message
     (send-client-finished-msg
      tls (make-client-finished-msg tls))

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
     ;; notify the client callback handler that there is new data
     (when (plusp (stream-size (rx-data-stream tls)))
       (when (read-fn tls)
	 (funcall (read-fn tls)
		  (data tls)
		  (stream-size (rx-data-stream tls))))))))

(defun send-client-hello (tls)
  (let ((hello (make-instance 'client-hello))
	(secpkey (make-secp256r1-keypair))
	(curve25519key (make-curve25519-keypair)))
    (setf
     (pubkey tls) (list (cons :secp256r1 secpkey)
			(cons :curve25519 curve25519key))
     (privkey tls) (list (cons :secp256r1 secpkey)
			 (cons :curve25519 curve25519key))
     (handshake-type hello) +CLIENT-HELLO+
     (random-bytes hello) (ironclad:random-data 32)
     (session-id hello) (list)
     (ciphers hello) (list
		      +TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384+
		      +TLS-AES-256-GCM-SHA384+)
     (compression hello) (list 0)
     (extensions hello) (list
			 (make-instance 'client-supported-versions
					:size (+ 1 (* 2 2))
					:extension-type +SUPPORTED-VERSIONS+
					:versions (list +TLS-1.3+ +TLS-1.2+))
			 (make-instance 'supported-groups
					:size (+ 2 (* 2 2))
					:named-groups (list +x25519+ +secp256r1+)
					:extension-type +SUPPORTED-GROUPS+)
			 (make-instance 'ec-point-formats
					:point-formats '(0)
					:size 2
					:extension-type +ec-point-formats+)
			 (make-instance 'server-name-ext
					:extension-type +server-name+
					:size (+ 2 (* 1 (+ 1 2 (length (peername tls)))))
					:names (list
						(make-instance
						 'server-name
						 :hostname (map '(vector (unsigned-byte 8))
								#'char-code (peername tls)))))
			 (make-instance 'signature-schemes
					:size (+ 2 (* 3 2))
					:extension-type +signature-algorithms+
					:signature-schemes
					(list
					 +rsa-pss-rsae-sha384+
					 +rsa-pkcs1-sha384+
					 +rsa-pkcs1-sha512+))
			 (make-client-keyshare
			  (list +x25519+ +secp256r1+)
			  (list
			   (public-key-bytes (cdr (assoc :curve25519 (pubkey tls))))
			   (public-key-bytes (cdr (assoc :secp256r1 (pubkey tls))))))))

    (setf
     (size hello)
     (+ 2 32 1 (length (session-id hello))
	2 (* 2 (length (ciphers hello)))
	1 (length (compression hello))
	2 (reduce #'+ (mapcar #'tls-extension-size (extensions hello)))))

    (let ((record (make-instance 'tls-record
				 :size (tls-size hello)
				 :protocol-version +TLS-1.0+
				 :content-type +RECORD-HANDSHAKE+)))
      (write-value (type-of record) (tx-stream tls) record)
      (write-value (type-of hello) (tx-stream tls) hello)

      (setf (client-random tls) (random-bytes hello))

      ;; update digest stream
      (write-value 'client-hello (digest-stream tls) hello)
      (on-read (socket tls) #'tls-client-rx tls))))

(defun get-version (hello)
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


(defmethod decrypt-record ((tls tls12-connection) hdr)
  (let* ((ciphertext (make-array (- (size hdr) 8) :element-type '(unsigned-byte 8)))
	 (nonce (get-in-nonce! tls))
	 (key (peer-key tls))
	 (explicit-iv (make-array 8 :element-type '(unsigned-byte 8)))
	 (salt-iv (peer-iv tls))
	 (iv nil)
	 (aead-data
	  (tls12-make-aead-data
	   nonce (content-type hdr)
	   (protocol-version hdr) (- (size hdr) 8 16))))
    (read-sequence explicit-iv (tls-rx-stream tls))
    (read-sequence ciphertext (tls-rx-stream tls))

    ;; prepare the IV
    (setf iv (concatenate '(vector (unsigned-byte 8)) salt-iv explicit-iv))
    (let* ((aead (make-aead-aes256-gcm key iv 0)))
      (let* ((plaintext (make-array (- (length ciphertext) 16) :element-type '(unsigned-byte 8))))
	(ironclad:process-associated-data aead aead-data)
	(multiple-value-bind (consumed produced)
	    (ironclad:decrypt
	     aead ciphertext plaintext
	     :handle-final-block t
	     :ciphertext-end (- (length ciphertext) 16))
	  (declare (ignore consumed produced)))

	(let ((state (state tls))
	      (type (tls-content->class (content-type hdr))))
	  (case state
	    (:NEGOTIATED
	     (ecase type
	       (application-data
		(write-sequence
		 plaintext (rx-data-stream tls) :start 0 :end (length plaintext)))
	       ((handshake alert)
		(let ((msg))
		  (with-input-from-sequence (in plaintext)
		    (setf msg (read-value type in)))
		  msg))))))))))

(defmethod tls12-encrypt-messages (tls msgs)
  (let* ((total-size (reduce #'+ (mapcar #'tls-size msgs)))
	 (key (my-key tls))
	 (explicit-iv (ironclad:random-data 8))
	 (salt-iv (my-iv tls))
	 (combined-iv (concatenate '(vector (unsigned-byte 8)) salt-iv explicit-iv)))
    (labels ((write-to-seq (msg)
	       (alien-ring::with-output-to-byte-sequence (out (+ 4 total-size))
		 (write-value (type-of msg) out msg))))
      (dolist (msg msgs)
	(let* ((plaintext (write-to-seq msg))
	       (len (length plaintext))
	       (nonce (get-out-nonce! tls))
	       (aead (make-aead-aes256-gcm key combined-iv 0))
	       (aead-data (tls12-make-aead-data nonce +RECORD-APPLICATION-DATA+ +TLS-1.2+ len))
	       (ciphertext (ironclad:encrypt-message aead plaintext :associated-data aead-data))
	       (rec (make-instance 'tls-record
				   :size (+ 8 len 16)
				   :content-type +RECORD-APPLICATION-DATA+)))
	  (write-value 'tls-record (tx-stream tls) rec)
	  (write-value 'raw-bytes (tx-stream tls) explicit-iv :size (length explicit-iv))
	  (write-sequence ciphertext (tx-stream tls))
	  (write-sequence (ironclad:produce-tag aead) (tx-stream tls)))))))
