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

(defun make-curve25519-keypair ()
  (let* ((kp (ironclad:generate-key-pair :curve25519)))
    (make-instance
     'curve25519-keypair
     :type :curve25519
     :private-key (ironclad:curve25519-key-x kp)
     :public-key (ironclad:curve25519-key-y kp))))

(defgeneric public-key-bytes (keypair))
(defgeneric private-key-bytes (keypair))

(defmethod public-key-bytes ((kp secp256r1-keypair))
  (let ((bytes (make-array 64 :element-type '(unsigned-byte 8)))
	(idx 0))
    (loop for elem across (public-key kp)
       do
	 (loop for b across (integer-to-octets elem)
	    do
	      (setf (aref bytes idx) b)
	      (incf idx)))
    bytes))

(defmethod public-key-bytes ((kp curve25519-keypair))
  (public-key kp))

(defgeneric diffie-hellman (n key))

(defmethod diffie-hellman (peer-pubkey (my-kp secp256r1-keypair))
  (let* ((d (private-key my-kp))
	 (peerx (octets-to-integer peer-pubkey 0 32))
	 (peery (octets-to-integer peer-pubkey 32 64))
	 (shared (multiply d (vector peerx peery 1) +curve-secp256r1+))
	 (zinv (modular-inverse (aref shared 2) (curve-order +curve-secp256r1+))))
    (integer-to-octets
     (mod (* (aref shared 0) zinv) (curve-order +curve-secp256r1+)))))

(defmethod diffie-hellman (peer-pubkey (my-kp curve25519-keypair))
  (let* ((privkey
	  (ironclad:make-private-key
	   :curve25519 :x (private-key my-kp) :y (public-key my-kp)))
	 (peerkey
	  (ironclad:make-public-key :curve25519 :y (subseq peer-pubkey 0 32))))
    (ironclad:diffie-hellman privkey peerkey)))
