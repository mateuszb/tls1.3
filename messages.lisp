(in-package :tls)

(eval-when (:compile-toplevel :load-toplevel :execute)
(defun slot->binding (spec stream)
  (destructuring-bind (name (type &rest args)) (normalize-slot-spec spec)
    `(,name (progn
	      (let ((val (read-value ',type ,stream ,@args)))
		(format t "read slot ~a of type ~a with value ~a~%" ',name ',type val)
		val)))))

(defun slot->keyword-arg (spec)
  (let ((name (first spec)))
    `(,(intern (symbol-name name) :keyword) ,name)))

(defun slot->defclass-slot (slot)
  (let ((name (first slot)))
    `(,name :initarg ,(intern (symbol-name name) :keyword) :accessor ,name)))

(defun normalize-slot-spec (spec)
  (list (first spec) (mklist (second spec))))

(defun mklist (x) (if (listp x) x (list x)))

(defun slot->read-value (slot stream)
  (destructuring-bind (name (type &rest args)) (normalize-slot-spec slot)
    `(progn
       (format t "reading slot ~a~%" ',type)
       (setf ,name (read-value ',type ,stream ,@args)))))

(defun slot->write-value (slot stream)
  (destructuring-bind (name (type &rest args)) (normalize-slot-spec slot)
    `(write-value ',type ,stream ,name ,@args)))

(defun slot->serialized-size-value (slot)
  (destructuring-bind (name (type &rest args)) (normalize-slot-spec slot)
    `(serialized-size ',type ,name ,@args)))

(defun all-slots (name)
  (nconc (direct-slots name) (inherited-slots name)))

(defun new-class-all-slots (slots superclasses)
  (nconc (mapcan #'all-slots superclasses) (mapcar #'first slots)))

(defun direct-slots (name)
  (copy-list (get name 'slots)))

(defun inherited-slots (name)
  (loop for super in (get name 'superclasses)
     nconc (direct-slots super)
     nconc (inherited-slots super))))

(defgeneric read-value (type stream &key))
(defgeneric write-value (type stream value &key))
(defgeneric serialized-size (type obj &key))

(defgeneric serialized-obj-size (obj)
  (:method-combination + :most-specific-last))

(defgeneric read-object (obj stream)
  (:method-combination progn :most-specific-last))

(defgeneric write-object (obj stream)
  (:method-combination progn :most-specific-last))

(defmethod read-value ((type symbol) stream &key)
  (format t "READING OBJ ~a~%" type)
  (let ((object (make-instance type)))
    (read-object object stream)
    object))

(defmethod write-value ((type symbol) stream value &key)
  (assert (typep value type))
  (write-object value stream))

(defmethod serialized-size ((type symbol) value &key)
  (assert (typep value type))
  (serialized-obj-size value))

(defmacro with-gensyms (syms &body body)
  `(let ,(loop for s in syms collect `(,s (gensym)))
     ,@body))

(defmacro define-binary-type (name (&rest args) &body spec)
  (ecase (length spec)
    (1
     (with-gensyms (type stream value)
       (destructuring-bind (derived-from &rest derived-args) (mklist (first spec))
	 `(progn
	    (defmethod read-value ((,type (eql ',name)) ,stream &key ,@args)
	      (read-value ',derived-from ,stream ,@derived-args))
	    (defmethod write-value ((,type (eql ',name)) ,stream ,value &key ,@args)
	      (write-value ',derived-from ,stream ,value ,@derived-args))
	    (defmethod serialized-size ((,type (eql ',name)) ,value &key ,@args)
	      (serialized-size ',derived-from ,value ,@derived-args))))))
    (3
     (with-gensyms (type)
       `(progn
	  ,(destructuring-bind ((in) &body body) (rest (assoc :reader spec))
	     `(defmethod read-value ((,type (eql ',name)) ,in &key ,@args)
		,@body))
	  ,(destructuring-bind ((out value) &body body) (rest (assoc :writer spec))
	     `(defmethod write-value ((,type (eql ',name)) ,out ,value &key ,@args)
		,@body))
	  ,(destructuring-bind ((value) &body body) (rest (assoc :size spec))
	     `(defmethod serialized-size ((,type (eql ',name)) ,value &key ,@args)
		,@body)))))))


;; TLS 1.3 sends integers in big-endian format
(define-binary-type unsigned-integer (bytes bits-per-byte)
  (:reader (in)
	   (loop with value = 0
	      for low-bit downfrom (* bits-per-byte (1- bytes)) to 0 by bits-per-byte
	      do (setf (ldb (byte bits-per-byte low-bit) value) (read-byte in))
	      finally (return value)))
  (:writer (out value)
	   (loop for low-bit downfrom (* bits-per-byte (1- bytes)) to 0 by bits-per-byte
	      do (write-byte (ldb (byte bits-per-byte low-bit) value) out)))
  (:size (value) bytes))

(define-binary-type u8 () (unsigned-integer :bytes 1 :bits-per-byte 8))
(define-binary-type u16 () (unsigned-integer :bytes 2 :bits-per-byte 8))
(define-binary-type u24 () (unsigned-integer :bytes 3 :bits-per-byte 8))
(define-binary-type u32 () (unsigned-integer :bytes 4 :bits-per-byte 8))
(define-binary-type u64 () (unsigned-integer :bytes 8 :bits-per-byte 8))

(define-binary-type generic-binary-string (length element-type)
  (:reader (in)
	   (let ((array (make-array length)))
	     (dotimes (i length)
	       (setf (aref array i) (read-value element-type in)))
	     array))
  (:writer (out binstr)
	   (dotimes (i length)
	     (write-value element-type out (aref binstr i))))
  (:size (value) length))

(defun val->bytes-needed (x)
  (let ((bits-needed (1+ (floor (log x 2)))))
    (/ (logand (+ bits-needed 7) (lognot 7)) 8)))

(define-binary-type vardata (min-len max-len element-type)
  (:reader (in)
	   (let* ((len-req (val->bytes-needed max-len))
		  (len-type (cond ((= len-req 1) 'u8) ((= len-req 2) 'u16) ((= len-req 4) 'u32) ((= len-req 8) 'u64)))
		  (len (read-value len-type in))
		  (arr (make-array len :element-type element-type)))
	     (format t "len-req ~a~%" len-req)
	     (format t "len type=~a~%" len-type)
	     (format t "len=~a~%" len)
	     (dotimes (i len)
	       (setf (aref arr i) (read-value element-type in)))
	     arr))
  (:writer (out data)
	   (let* ((type (case (val->bytes-needed max-len) (1 'u8) (2 'u16) (4 'u32) (8 'u64))))
	     (when (or (< (length data) min-len)
		       (> (length data) max-len))
	       (error (format nil "Length ~a out of bounds ~a:~a" (length data) min-len max-len)))
	     (write-value type out (loop for el across data sum (serialized-size element-type el)))
	     (dotimes (i (length data))
	       #+debug
	       (format t "writing value of type ~a from array ~a~%" element-type data)
	       (write-value element-type out (aref data i)))))
  (:size (data)
	 (format t "checking size of vardata ~a of element type ~a~%" data element-type)
	 (+ (val->bytes-needed max-len)
	    (loop for el across data
	       sum (serialized-size element-type el)))))

(defmacro define-generic-binary-class (name (&rest superclasses) slots read-method)
  (with-gensyms (objectvar streamvar)
    `(progn
       (eval-when (:compile-toplevel :load-toplevel :execute)
	 (setf (get ',name 'slots) ',(mapcar #'first slots))
	 (setf (get ',name 'superclasses) ',superclasses))

       (defclass ,name ,superclasses
	 ,(mapcar #'slot->defclass-slot slots))

       ,read-method

       (defmethod write-object progn ((,objectvar ,name) ,streamvar)
		  (declare (ignorable ,streamvar))
		  (with-slots ,(new-class-all-slots slots superclasses) ,objectvar
		    ,@(mapcar #'(lambda (x) (slot->write-value x streamvar)) slots)))

       (defmethod serialized-obj-size + ((,objectvar ,name))
		  (with-slots ,(new-class-all-slots slots superclasses) ,objectvar
		    (+ ,@(mapcar #'(lambda (x) (slot->serialized-size-value x)) slots)))))))

(defmacro define-binary-class (name (&rest superclasses) slots)
  (with-gensyms (objectvar streamvar)
    `(define-generic-binary-class ,name ,superclasses ,slots
       (defmethod read-object progn ((,objectvar ,name) ,streamvar)
	 (declare (ignorable ,streamvar))
	 (format t "reading obj of type ~a~%" ',name)
	 (with-slots ,(new-class-all-slots slots superclasses) ,objectvar
	   ,@(mapcar #'(lambda (x) (slot->read-value x streamvar)) slots))))))


(defmacro define-tagged-binary-class (name (&rest superclasses) slots &rest options)
  (with-gensyms (typevar objectvar streamvar)
    `(define-generic-binary-class ,name ,superclasses ,slots
      (defmethod read-value ((,typevar (eql ',name)) ,streamvar &key)
	(let* ,(mapcar #'(lambda (x) (slot->binding x streamvar)) slots)
	  (format t "read-value of type ~a~%" ',name)
	  (let ((,objectvar
		 (make-instance
		  ,@(or (cdr (assoc :dispatch options))
			(error "Must supply :dispatch form."))
		  ,@(mapcan #'slot->keyword-arg slots))))
	    (format t "created object ~a~%" (type-of ,objectvar))
	    (read-object ,objectvar ,streamvar)
	    ,objectvar))))))

(defun find-handshake-class (msgenum)
  (format t "locating type of handshake record ~a~%" msgenum)
  (cond
    ((= msgenum +CLIENT-HELLO+) 'client-hello)
    ((= msgenum +SERVER-HELLO+) 'server-hello)
    ((= msgenum +NEW-SESSION-TICKET+) 'new-session-ticket)
    ((= msgenum +END-OF-EARLY-DATA+) 'end-of-early-data)
    ((= msgenum +ENCRYPTED-EXTENSIONS+) 'encrypted-extensions)
    ((= msgenum +CERTIFICATE+) 'certificate)
    ((= msgenum +CERTIFICATE-REQUEST+) 'certificate-request)
    ((= msgenum +CERTIFICATE-VERIFY+) 'certificate-verify)
    ((= msgenum +FINISHED+) 'finished)
    ((= msgenum +KEY-UPDATE+) 'key-update)
    ((= msgenum +MESSAGE-HASH+) 'message-hash)))

(defun find-handshake-enum (msgtype)
  (case msgtype
    (client-hello +CLIENT-HELLO+)
    (server-hello +SERVER-HELLO+)
    (new-session-ticket +NEW-SESSION-TICKET+)
    (end-of-early-data +END-OF-EARLY-DATA+)
    (encrypted-extensions +ENCRYPTED-EXTENSIONS+)
    (certificate +CERTIFICATE+)
    (certificate-request +CERTIFICATE-REQUEST+)
    (certificate-verify +CERTIFICATE-VERIFY+)
    (finished +FINISHED+)
    (key-update +KEY-UPDATE+)
    (message-hash +MESSAGE-HASH+)))

;;       uint16 ProtocolVersion;
;;       opaque Random[32];
;;       uint8 CipherSuite[2];    /* Cryptographic suite selector */
;;
;;       struct {
;;           ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
;;           Random random;
;;           opaque legacy_session_id<0..32>;
;;           CipherSuite cipher_suites<2..2^16-2>;
;;           opaque legacy_compression_methods<1..2^8-1>;
;;           Extension extensions<8..2^16-1>;
;;       } ClientHello;

(define-binary-type opaque-random ()
  (:reader (in)
	   (read-value 'generic-binary-string in :length 32 :element-type 'u8))
  (:writer (out val)
	   (write-value 'generic-binary-string out val :length 32 :element-type 'u8))
  (:size (val) 32))

(defun find-extension-class (id)
  (cond
    ((= id +supported-versions+) 'supported-versions)
    ((= id +signature-algorithms+) 'signature-algorithms)
    ((= id +supported-groups+) 'supported-groups)
    ((= id +pre-shared-key+) 'pre-shared-key)
    ((= id +psk-key-exchange-modes+) 'psk-key-exchange-modes)
    ((= id +server-name+) 'server-name)
    (t (error "Unknown extension"))))

(defun find-server-extension-class (id)
  (cond
    ((= id +supported-versions+) 'supported-version)
    ((= id +signature-algorithms+) 'signature-algorithms)
    ((= id +supported-groups+) 'supported-groups)
    ((= id +pre-shared-key+) 'pre-shared-key)
    ((= id +psk-key-exchange-modes+) 'psk-key-exchange-modes)
    ((= id +server-name+) 'server-name)
    ((= id +key-share+) 'server-key-share)
    (t (error "Unknown extension"))))

(define-tagged-binary-class extension ()
  ((extension-type u16)
   (extension-len u16))
  (:dispatch
   (progn
     (format t "extension type: ~a, len: ~a~%" extension-type extension-len)
     (find-extension-class extension-type))))

(define-tagged-binary-class server-extension ()
  ((extension-type u16)
   (extension-len u16))
  (:dispatch
   (progn
     (format t "extension type: ~a, len: ~a~%" extension-type extension-len)
     (find-server-extension-class extension-type))))

(define-binary-class supported-versions (extension)
  ((versions (vardata :min-len 1 :max-len 127 :element-type 'u16))))

(define-binary-class supported-version (server-extension)
  ((version u16)))

(define-binary-class supported-signatures (extension)
  ((signatures (vardata :min-len 1 :max-len (1- (ash 1 15)) :element-type 'u16))))

(define-binary-class supported-groups (extension)
  ((groups (vardata :min-len 1 :max-len (1- (ash 1 15)) :element-type 'u16))))

(define-binary-class key-share-entry ()
  ((group u16)
   (key-data (vardata :min-len 1 :max-len (1- (ash 1 16)) :element-type 'u8))))

(define-binary-class key-share (extension)
  ((keys (vardata :min-len 1 :max-len (1- (ash 1 16)) :element-type 'key-share-entry))))

(define-binary-class server-key-share (server-extension)
  ((key key-share-entry)))

(define-binary-class server-name ()
  ((name-type u8)
   (hostname (vardata :min-len 1 :max-len (1- (ash 1 16)) :element-type 'u8))))

(define-binary-class server-name-indication (extension)
  ((hostnames (vardata :min-len 1 :max-len (1- (ash 1 16)) :element-type 'server-name))))

(define-binary-class psk-identity ()
  ((identity-data (vardata :min-len 1 :max-len (1- (ash 1 16)) :element-type 'u8))
   (obfuscated-ticket-age u32)))

(define-binary-type psk-identities ()
  (:reader (in)
	   (let* ((n (read-value 'u16 in)))
	     (loop for i from 0 below n
		collect (read-value 'psk-identity in))))
  (:writer (out identities)
	   (write-value 'u16 out (length identities))
	   (loop for id in identities
	      do (write-value 'psk-identity out id)))
  (:size (identities)
	 (+ 2 (loop for id in identities sum (serialized-size 'psk-identity id)))))

(define-binary-class psk-binder ()
  ((data (vardata :min-len 32 :max-len 255 :element-type 'u8))))

(define-binary-type psk-binders ()
  (:reader (in)
	   (let ((n (read-value 'u16 in)))
	     (loop for i from 0 below n
		  collect (read-value 'psk-binder in))))
  (:writer (out binders)
	   (write-value 'u16 out (length binders))
	   (loop for b in binders
	      do (write-value 'psk-binder out b)))
  (:size (val)
	 (+ 2 (loop for b in val sum (serialized-size 'psk-binder b)))))

(define-binary-class offered-psks (extension)
  ((identities psk-identities)
   (binders psk-binders)))

(define-binary-type tls-extensions ()
  (:reader (in)
	   (let ((n (read-value 'u16 in)))
	     (loop for i from 0 below n
		collect (read-value 'extension in))))
  (:writer (out exts)
	   (write-value 'u16 out (reduce #'+ (mapcar (lambda (x) (serialized-size (type-of x) x)) exts)))
	   (loop for ext in exts
	      do
		(write-value (type-of ext) out ext)))
  (:size (val)
	 (+ 2 (loop for ext in val sum (serialized-size (type-of ext) ext)))))

(define-binary-type tls-server-extensions ()
  (:reader (in)
   (let ((n (read-value 'u16 in)))
     (loop
	with i = 0
	while (< i n)
	collect (let ((val (read-value 'server-extension in)))
		  (incf i (serialized-size (type-of val) val))
		  val) into exts
	finally
	  (return exts))))
  (:writer (out exts)
   (write-value 'u16 out (reduce #'+ (mapcar (lambda (x) (serialized-size (type-of x) x)) exts)))
   (loop for ext in exts
      do
	(write-value (type-of ext) out ext)))
  (:size (val)
	 (+ 2 (loop for ext in val sum (serialized-size (type-of ext) ext)))))

(define-binary-class handshake (record)
  ((msgtype u8)
   (msglen u24)
   (resp server-hello))
  
  ;(:dispatch (find-handshake-class msgtype))
  )

(define-binary-class client-hello (handshake)
  ((legacy-version u16)
   (rnd opaque-random)
   (session-id (vardata :min-len 0 :max-len 32 :element-type 'u8))
   (cipher-suites (vardata :min-len 1 :max-len 32767 :element-type 'u16))
   (legacy-compression-methods (vardata :min-len 1 :max-len 1 :element-type 'u8))
   (extensions tls-extensions)))

(define-binary-class server-hello ()
  ((legacy-version u16)
   (rnd opaque-random)
   (session-id (vardata :min-len 0 :max-len 32 :element-type 'u8))
   (cipher-suite u16)
   (legacy-compression-method u8)
   (extensions tls-server-extensions)))

(defun find-record-class (content-type)
  (format t "locating class with content type ~a~%" content-type)
  (cond
    ((= content-type +RECORD-INVALID+) 'record-invalid)
    ((= content-type +RECORD-CHANGE-CIPHER-SPEC+) 'change-cipher-spec)
    ((= content-type +RECORD-ALERT+) 'alert)
    ((= content-type +RECORD-HANDSHAKE+) 'handshake)
    ((= content-type +RECORD-APPLICATION-DATA+) 'application-data)
    ((= content-type +RECORD-HEARTBEAT+) 'heartbeat)))

(defun msg->record (msg)
  (case (type-of msg)
    (handshake +RECORD-HANDSHAKE+)))

(define-tagged-binary-class record ()
  ((content-type u8)
   (protocol-version u16)
   (len u16))
  (:dispatch
   (find-record-class content-type)))

(defun write-record (stream msg)
  (write-value 'u8 stream (msg->record msg))
  (write-value 'u16 stream +TLS-1.2+)
  (write-value 'u16 stream (serialized-size (type-of msg) msg))
  (write-value (type-of msg) stream msg))

(defun read-record (stream)
  (read-value 'record stream))
