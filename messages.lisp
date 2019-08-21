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
    `(setf ,name (read-value ',type ,stream ,@args))))

(defun slot->write-value (slot stream)
  (destructuring-bind (name (type &rest args)) (normalize-slot-spec slot)
    `(write-value ',type ,stream ,name ,@args)))

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

(defgeneric read-object (obj stream)
  (:method-combination progn :most-specific-last))

(defgeneric write-object (obj stream)
  (:method-combination progn :most-specific-last))

(defmethod read-value ((type symbol) stream &key)
  (let ((object (make-instance type)))
    (read-object object stream)
    object))

(defmethod write-value ((type symbol) stream value &key)
  (assert (typep value type))
  (write-object value stream))

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
	      (write-value ',derived-from ,stream ,value ,@derived-args))))))
    (2
     (with-gensyms (type)
       `(progn
	  ,(destructuring-bind ((in) &body body) (rest (assoc :reader spec))
	     `(defmethod read-value ((,type (eql ',name)) ,in &key ,@args)
		,@body))
	  ,(destructuring-bind ((out value) &body body) (rest (assoc :writer spec))
	     `(defmethod write-value ((,type (eql ',name)) ,out ,value &key ,@args)
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
	      do (write-byte (ldb (byte bits-per-byte low-bit) value) out))))

(define-binary-type u8 () (unsigned-integer :bytes 1 :bits-per-byte 8))
(define-binary-type u16 () (unsigned-integer :bytes 2 :bits-per-byte 8))
(define-binary-type u24 () (unsigned-integer :bytes 3 :bits-per-byte 8))
(define-binary-type u32 () (unsigned-integer :bytes 4 :bits-per-byte 8))
(define-binary-type u64 () (unsigned-integer :bytes 8 :bits-per-byte 8))

(define-binary-type binary-string (length element-type)
  (:reader (in)
	   (let ((array (make-array length)))
	     (dotimes (i length)
	       (setf (aref array i) (read-value element-type in)))
	     array))
  (:writer (out binstr)
	   (dotimes (i length)
	     (write-value element-type out (aref binstr i)))))

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
		    ,@(mapcar #'(lambda (x) (slot->write-value x streamvar)) slots))))))

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



