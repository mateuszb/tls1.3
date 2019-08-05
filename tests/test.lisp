(defpackage tls/tests
  (:use :cl :prove :tls :flexi-streams))
(in-package :tls/tests)

(defun test-binary-type-size-test ()
  (is (serialized-size 'tls::u8 0) 1)
  (is (serialized-size 'tls::u16 0) 2)
  (is (serialized-size 'tls::u32 0) 4)
  (is (serialized-size 'tls::u64 0) 8))

(defun test-binary-class-size-test ()
  (let ((obj (make-instance 'tls::psk-identity
			    :obfuscated-ticket-age 100
			    :identity-data (make-array 10))))
    (is (serialized-size 'tls::psk-identity obj) (+ 2 10 4))

    (is (serialized-size 'tls::psk-identities (list obj obj obj)) (+ 2 (* 3 (+ 2 10 4))))))

(defun test-client-hello-invalid ()
  (let ((hellomsg (make-instance 'tls::client-hello)))
    (with-slots (tls::legacy-version
		 tls::rnd
		 tls::session-id
		 (cipher-suites tls::cipher-suites)
		 tls::legacy-compression-methods
		 tls::extensions) hellomsg
      (let* ((ciphers (make-array 1 :initial-element tls::+tls-aes-256-gcm-sha384+))
	     (randbytes (make-array 32 :initial-element 65))
	     (sid (make-array 32 :initial-element 66))
	     (compression-methods #(0))
	     (supp-ver-ext (make-instance 'tls::supported-versions :versions #(#x0304)
					  :extension-len 0
					  :extension-type tls::+supported-versions+))
	     (supp-sigs (make-instance 'tls::supported-signatures
				       :signatures
				       (make-array
					8
					:initial-contents
					(list
					 tls::+ecdsa-secp256r1-sha256+
					 tls::+rsa-pss-rsae-sha256+
					 tls::+rsa-pkcs1-sha256+
					 tls::+ecdsa-secp384r1-sha384+
					 tls::+rsa-pss-rsae-sha384+
					 tls::+rsa-pkcs1-sha384+
					 tls::+rsa-pss-rsae-sha512+
					 tls::+ed25519+
					 ))
				       :extension-len 18
				       :extension-type tls::+signature-algorithms+))
	     (supp-groups (make-instance 'tls::supported-groups
					 :extension-type tls::+supported-groups+
					 :extension-len 8
					 :groups (make-array 3
							     :initial-contents
							     (list
							      tls::+x25519+
							      tls::+secp256r1+
							      tls::+secp384r1+))))
	     (keydata (make-instance 'tls::key-share-entry :key-data #(53 128 114 214 54 88 128 209 174 234 50 154 223 145 33 56 56 81 237 33 162 142 59 117 233 101 208 210 205 22 98 84) :group tls::+x25519+))
	     (keyex (make-instance 'tls::key-share
				   :extension-type tls::+key-share+
				   :extension-len 38
				   :keys (make-array 1 :initial-element keydata)))
	     (sni (make-instance 'tls::server-name-indication
				 :extension-type tls::+server-name+
				 :extension-len 17
				 :hostnames
				 (make-array
				  1
				  :initial-element (make-instance
						    'tls::server-name
						    :name-type 0
						    :hostname
						    (make-array 12 :initial-contents
								(map 'list #'char-code "dev.test.com"))))))

	     (extensions (list sni supp-groups supp-sigs keyex supp-ver-ext)))

	(setf (slot-value supp-ver-ext 'tls::extension-len)
	      (serialized-size 'tls::vardata #(#x0304) :element-type 'tls::u16 :max-len 127 :min-len 1))

	(setf tls::legacy-version tls::+TLS-1.2+
	      tls::rnd randbytes
	      tls::session-id sid
	      cipher-suites ciphers
	      tls::legacy-compression-methods compression-methods
	      tls::extensions extensions)

	(format t "extensions serialized size is ~a~%"
		(reduce #'+
			(mapcar (lambda (x)
				  (serialized-size (type-of x) x)) extensions)))

	(with-open-file (out "out.bin" :if-does-not-exist :create
			     :if-exists :overwrite :direction :output :element-type '(unsigned-byte 8))
	  (let ((handshake (make-instance 'tls::handshake
					  :msgtype tls::+CLIENT-HELLO+
					  :msglen (tls::serialized-size (type-of hellomsg) hellomsg)
					  :msg hellomsg)))

	    (format t "size of the supported versions extension: ~a~%"
		    (tls::serialized-size 'tls::supported-versions supp-ver-ext))
	    (tls::write-record out handshake)
	    ;(write-value 'tls::handshake out handshake)
	    ))))))

(defun server-hello-parse-test ()
  (with-open-file (in "server-hello.bin" :direction :input :element-type '(unsigned-byte 8))
    (tls::read-value 'tls::record in)))

(plan 4)
(test-binary-type-size-test)
;(test-binary-class-size-test)
;(test-client-hello-invalid)
(server-hello-parse-test)
(finalize)
