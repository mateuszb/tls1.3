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

(defun make-client-keyshare (groups keys)
  (let ((key-shares
	 (loop
	    for key in keys
	    for group in groups
	    collect
	      (make-instance 'key-share
			     :key-exchange key
			     :named-group group))))
    (make-instance
     'client-hello-key-share
     :key-shares key-shares
     :size (+ 2 (reduce #'+ (mapcar #'key-share-size key-shares)))
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
   :random-bytes (ironclad:random-data 32)
   :compression '(0)
   :extensions extensions
   :handshake-type +CLIENT-HELLO+
   :size (+
	  2 32 (1+ (length session-id))
	  2 (* 2 (length supported-ciphers))
	  2 ;; compression schemes (we send only 1)
	  (reduce #'+ (mapcar #'tls-extension-size extensions)))))

(defun make-server-hello (selected-cipher session-id extensions)
  (make-instance 'server-hello
		 :session-id session-id
		 :selected-cipher selected-cipher
		 :random-bytes (ironclad:random-data 32)
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
