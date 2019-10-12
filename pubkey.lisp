(in-package :tls)

(defclass keypair ()
  ((public-key :initarg :public-key :initform nil :reader public-key)
   (private-key :initarg :private-key :initform nil :reader private-key)
   (type :initarg :type :initform nil :reader key-type)))

(defclass curve25519-keypair (keypair) nil)
(defclass secp256r1-keypair (keypair) nil)

(defun make-secp256r1-keypair ()
  (let* ((secret-bytes (ironclad:random-data 32))
	 (d (octets-to-integer secret-bytes 0 32))
	 (order (curve-order +curve-secp256r1+))
	 (P (projective-base-point +curve-secp256r1+))
	 (dP (multiply d P +curve-secp256r1+))
	 (zinv (modular-inverse (aref dP 2) order))
	 (pubx (mod (* (aref dP 0) zinv) order))
	 (puby (mod (* (aref dP 1) zinv) order))
	 (pubkey (vector pubx puby)))
    (make-instance
     'secp256r1-keypair :type :secp256r1 :private-key d :public-key pubkey)))

(defun make-secp256r1-public-key (pubkey-bytes)
  (let* ((x (octets-to-integer pubkey-bytes 0 32))
	 (y (octets-to-integer pubkey-bytes 32 64)))
    (make-instance
     'secp256r1-keypair :type :secp256r1 :private-key nil :public-key (vector x y))))

(defun make-curve25519-public-key (key-bytes)
  (let* ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-contents key-bytes))
	 (y (octets-to-integer bytes 0 32)))
    (make-instance 'curve25519-keypair :type :curve25519 :public-key y)))

(defun make-curve25519-keypair ()
  (multiple-value-bind (kpriv kpub) (ironclad:generate-key-pair :curve25519)
    #+debug
    (format t "my key pair:~%private.x=~a,~%private.y=~a~%public.y=~a~%"
     (ironclad:byte-array-to-hex-string
      (ironclad:curve25519-key-x kpriv))
     (ironclad:byte-array-to-hex-string
      (ironclad:curve25519-key-y kpriv))
     (ironclad:byte-array-to-hex-string
      (ironclad:curve25519-key-y kpub)))

    (make-instance
     'curve25519-keypair
     :type :curve25519
     :private-key (octets-to-integer (ironclad:curve25519-key-x kpriv) 0 32)
     :public-key (octets-to-integer (ironclad:curve25519-key-y kpub) 0 32))))

(defgeneric public-key-bytes (keypair))
(defgeneric private-key-bytes (keypair))

(defmethod public-key-bytes ((kp secp256r1-keypair))
  (let ((bytes (make-array 65 :element-type '(unsigned-byte 8)))
	(idx 1))
    (setf (aref bytes 0) 4)
    (loop for elem across (public-key kp)
       do
	 (loop for b across (integer-to-octets elem)
	    do
	      (setf (aref bytes idx) b)
	      (incf idx)))
    bytes))

(defmethod private-key-bytes ((kp curve25519-keypair))
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (loop
       for i from 0 below 32
       for j from 248 downto 0 by 8
       with v = (private-key kp)
       do (setf (aref bytes i) (ldb (byte 8 j) v)))
    bytes))

(defmethod public-key-bytes ((kp curve25519-keypair))
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (loop
       for i from 0 below 32
       for j from 248 downto 0 by 8
       with v = (public-key kp)
       do (setf (aref bytes i) (ldb (byte 8 j) v)))
    bytes))

(defgeneric diffie-hellman (n key))

(defmethod diffie-hellman (peer-pubkey (my-kp secp256r1-keypair))
  (declare (optimize (debug 3) (speed 0)))
  (let* ((d (private-key my-kp))
	 (peerx (aref (public-key peer-pubkey) 0))
	 (peery (aref (public-key peer-pubkey) 1))
	 (shared (multiply d (vector peerx peery 1) +curve-secp256r1+))
	 (zinv (modular-inverse (aref shared 2) (curve-order +curve-secp256r1+))))
    (integer-to-octets
     (mod (* (aref shared 0) zinv) (curve-order +curve-secp256r1+)))))

(defmethod diffie-hellman (peer-pubkey (my-kp curve25519-keypair))
  (declare (optimize (debug 3) (speed 0)))
  (let* ((privkey (ironclad:make-private-key
		   :curve25519 :x (private-key-bytes my-kp) :y (public-key my-kp)))
	 (peerkey (ironclad:make-public-key
		   :curve25519 :y (public-key-bytes peer-pubkey))))
    (ironclad:diffie-hellman privkey peerkey)))
