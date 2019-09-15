(in-package :tls)

(defun make-server-keyshare (group key-bytes)
  (let ((key-share
	 (make-instance 'key-share
			:key-exchange key-bytes
			:named-group group)))
    (make-instance 'server-hello-key-share
		   :key key-share
		   :size (key-share-size key-share)
		   :extension-type +key-share+)))

(defun make-client-keyshare (group key-bytes)
  (let ((key-share
	 (make-instance 'key-share
			:key-exchange key-bytes
			:named-group group)))
    (make-instance 'client-hello-key-share
		   :key-shares (list key-share)
		   :size (+ 2 (key-share-size key-share))
		   :extension-type +key-share+)))

(defun make-server-supported-versions ()
  (make-instance 'server-supported-versions
		 :version +TLS-1.3+
		 :size 2
		 :extension-type +supported-versions+))

(defun extension-size (ext)
  (+ 2 (slot-value ext 'size)))

(defun make-client-hello (supported-ciphers session-id extensions)
  (make-instance
   'client-hello
   :session-id session-id
   :ciphers supported-ciphers
   :compression '(0)
   :extensions extensions
   :handshake-type +CLIENT-HELLO+
   :size (+
	  2 32 (1+ (length session-id))
	  2 (* 2 (length supported-ciphers))
	  2 ;; compression schemes (we send only 1)
	  (reduce #'+ (mapcar #'tls-extension-size extensions)))))

(defun make-server-hello (selected-cipher session-id extensions)
  (format t "extensions length = ~a~%"
	  (reduce #'+ (mapcar #'tls-extension-size extensions)))
  (make-instance 'server-hello
		 :session-id session-id
		 :selected-cipher selected-cipher
		 :handshake-type +SERVER-HELLO+
		 :extensions extensions
		 :size (+
			2  ; protocol version
			32 ; random
			(1+ (length session-id)) ; session id
			2 ; cipher suite
			1 ; compression id
			2 ; extensions length
			(reduce #'+ (mapcar #'tls-extension-size extensions)))))
