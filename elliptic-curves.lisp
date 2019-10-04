(in-package :tls)
;; helper functions
(defun integer-octets (x)
  (declare (optimize (speed 3) (debug 0))
	   (type integer x))
  (ceiling (integer-length x) 8))

(defun integer-bits (x)
  (declare (optimize (speed 3) (debug 0))
	   (type integer x))
  (integer-length x))

(defun integer-to-octets (point)
  (let* ((nbytes (integer-octets point))
	 (nbits (* nbytes 8))
	 (octets (make-array nbytes :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop
       for i from (- nbits 8) downto 0 by 8
       for j from 0 upto (1- nbytes) by 1
       do
	 (setf (aref octets j) (ldb (byte 8 i) point)))
    octets))

;; point formats defined in SEC-1 document at
;; https://www.secg.org/sec1-v2.pdf
(defun octets-to-integer (octets start end)
  (let ((nbits (* (- end start) 8)))
    (loop
       for i from start upto end
       for j from (- nbits 8) downto 0 by 8
       with result = 0
       do
	 (setf (ldb (byte 8 j) result) (aref octets i))
       finally (return result))))

(defun extended-gcd (a b)
  (do ((u (vector 1 0 a))
       (v (vector 0 1 b)))
      ((zerop (aref v 2)) (values u v))
    (let* ((q (floor (/ (aref u 2) (aref v 2))))
	   (vv (map 'vector #'- u (map 'vector #'* v (vector q q q)))))
      (setf u v v vv))))

#+off
(defun modular-inverse (a p)
  (format t "modular inverse~%")
  (mod (expt a (- p 2)) p))

(defun modular-inverse (a p)
  (let ((v (extended-gcd a p)))
    (mod (aref v 0) p)))

(defclass curve ()
  ((order :initform nil :accessor curve-order :initarg :order)
   (a :initform nil :accessor curve-a :initarg :a)
   (b :initform nil :accessor curve-b :initarg :b)
   (base-point :initform nil :accessor base-point :initarg :base-point)
   (n :initform nil :accessor curve-n :initarg :n)
   (h :initform nil :accessor curve-h :initarg :h)))

#+off
(defun all-non-negative-p (x)
  (and (vectorp x)
       (every #'numberp x)
       (or
	(every #'zerop x)
	(every #'plusp x))))

#+off
(deftype curve-point () '(and (vector integer 3) (satisfies all-non-negative-p)))

(defgeneric p-bytes (curve-class))
(defgeneric decode-point-from-octets (octets curve-class))
(defgeneric mul2 (point curve))
(defgeneric neg (point curve))

(defgeneric projective-base-point (c))
(defmethod projective-base-point ((c curve))
  (vector (svref (base-point c) 0) (svref (base-point c) 1) 1))

(defun is-zero? (point)
  (and (zerop (aref point 0))
       (zerop (aref point 2))
       (= (aref point 1))))

(defmacro defcurve (name (p a b g n h))
  (let ((class-name (intern (string-upcase (format nil "curve-~a" name))))
	(param-name (intern (string-upcase (format nil "+curve-~a+" name)))))
    `(progn
       (defclass ,class-name (curve) nil)
       (defmethod p-bytes ((curve-class (eql ',class-name))) (ceiling (log ,p 256)))
       (defmethod decode-point-from-octets (octets (curve-class (eql ',class-name)))
	 (let ((b (aref octets 0))
	       (len (length octets))
	       (plen (p-bytes ',class-name)))
	   (cond
	     ((= b 0) (vector 0 0))
	     ((= len (1+ plen)) (error "compressed format is not unsupported"))
	     ((= len (1+ (* 2 plen)))
	      (assert (= b 4))
	      (values
	       (octets-to-integer octets 1 (1+ plen))
	       (octets-to-integer octets (1+ plen) (length octets)))))))

       (defmethod neg (point (curve ,class-name))
	 (if (and (zerop (aref point 0))
		  (zerop (aref point 2))
		  (= (aref point 1) 1))
	     point
	     (vector (aref point 0)
		     (- (aref point 1))
		     (aref point 2))))
	 
       (defmethod mul2 (point (curve ,class-name))
	 (let ((x (svref point 0))
	       (y (svref point 1))
	       (z (svref point 2)))
	   (declare (type integer x y z))
	   (cond
	     ((or (is-zero? point) (zerop y)) (vector 0 1 0))
	     (t
	      (labels ((mul (x y) (mod (* x y) ,p))
		       (add (x y) (mod (+ x y) ,p))
		       (sub (x y) (mod (- x y) ,p)))
		(let* ((x^2  (mul x x))
		       (3x^2 (mul 3 x^2))
		       (z^2  (mul z z))
		       (az^2 (mul ,a z^2))
		       (m    (add 3x^2 az^2))
		       (yz   (mul y z))
		       (u    (mul 2 yz))
		       (ux   (mul u x))
		       (uxy  (mul ux y))
		       (v    (mul 2 uxy))
		       (m^2  (mul m m))
		       (2v   (mul v 2))
		       (w    (sub m^2 2v))
		       (rx   (mul u w))
		       (u^2  (mul u u))
		       (y^2  (mul y y))
		       (uuyy (mul u^2 y^2))
		       (ry   (sub (mul m (sub v w)) (mul 2 uuyy)))
		       (rz   (mul u u^2)))
		  (vector rx ry rz)))))))

       (defmethod add (point1 point2 (curve ,class-name))
	 (let ((x1 (svref point1 0))
	       (y1 (svref point1 1))
	       (z1 (svref point1 2))
	       (x2 (svref point2 0))
	       (y2 (svref point2 1))
	       (z2 (svref point2 2)))
	   (declare (type integer x1 y1 z1 x2 y2 z2))
	   (cond
	     ((and (zerop x1) (zerop z1) (= y1 1)) point2)
	     ((and (zerop x2) (zerop z2) (= y2 1)) point1)

	     ;; x0 == x1? && y0 != y1 then P1 + P2 = O	   
	     ((= (mod (* x1 z2) ,p) (mod (* z1 x2) ,p)) (vector 0 1 0))

	     (t
	      (labels ((mul (x y) (mod (* x y) ,p))
		       (sub (x y) (mod (- x y) ,p))
		       (add (x y) (mod (+ x y) ,p)))
		(let* ((t0 (mul y1 z2))  ; t0 = y1 * z2
		       (t1 (mul y2 z1))  ; t1 = y2 * z1
		       (tt (sub t0 t1))  ; tt = t0 - t1
		       (u0 (mul x1 z2))  ; u0 = x1 * z2
		       (u1 (mul x2 z1))  ; u1 = x2 * z1
		       (u  (sub u0 u1))  ; u = u0 - u1
		       (u2 (mul u u))    ; u2 = u^2
		       (v  (mul z1 z2))  ; v = z1 * z2
		       (t3 (mul tt tt))  ; t3 = tt^2
		       (t4 (mul t3 v))   ; t4 = tt^2 * v
		       (t5 (add u0 u1))  ; t5 = u1 + u2
		       (t6 (mul u2 t5))  ; t6 = uu * (u1 + u2)
		       (w  (sub t4 t6))  ; w = tt^2*v - uu * (u1 + u2)
		       (u3 (mul u u2))   ; u3 = u * u^2
		       (rx (mul u w))    ; result-x = u * w
		       (t7 (mul u0 u2))  ; t7 = u0 * u2
		       (t8 (sub t7 w))   ; t8 = u0 * u2 - w
		       (t9 (mul tt t8))  ; t9 = t * (u0 * u2 - w)
		       (s1 (mul t0 u3))  ; s1 = t0 * u3
		       (ry (sub t9 s1))  ; result-y = t9 - s1
		       (rz (mul u3 v)))
		  (declare (type (integer 0 ,(1- (ash 1 (integer-length p))))
				 t0 t1 tt u0 u1 u u2 v t3 t4
				 t5 t6 w u3 rx t7 t8 t9 s1 ry rz))
		  (vector rx ry rz)))))))

       (defmethod multiply (n point (curve ,class-name))
	 (declare (type integer n)
		  (optimize (debug 3) (speed 0)))
	 (let ((x (svref point 0))
	       (y (svref point 1))
	       (z (svref point 2)))
	   (declare (type integer x y z))
	   (cond
	     ((< n 0) (multiply (- n) (vector x (- y) z) curve))
	     ((= n 0) (vector 0 1 0))
	     (t
	      (let ((Q point)
		    (R (if (oddp n) point (vector 0 1 0))))
		(loop
		   for i = (ash n -1) then (ash i -1)
		   while (plusp i)
		   do
		     (setf Q (mul2 Q curve))
		     (when (logbitp 0 i)
		       (setf R (add Q R curve))))
		R)))))
       
       (defparameter ,param-name
	 (multiple-value-bind (x y) (decode-point-from-octets (integer-to-octets ,g) ',class-name)
	   (make-instance ',class-name
			  :order ,p
			  :a ,a
			  :b ,b
			  :base-point (vector x y)
			  :n ,n
			  :h ,h))))))

;; all of the elliptic curves are defined over the polynomial
;;
;; y^2 = x^3 + ax + b over F_p
;;
;; here I only define elliptic curves over the prime fields

;; Curve parameters are from: https://www.secg.org/SEC2-Ver-1.0.pdf
;; NIST P-256 curve
(defcurve secp256r1
    (#xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
     #xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
     #x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
     #x046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
     #xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
     1))

(defmacro defcurvetest (curve k correct-x correct-y)
  `(let ((base (projective-base-point ,curve)))
     (let* ((result (multiply ,k base ,curve))
	    (x (svref result 0))
	    (y (svref result 1))
	    (z (svref result 2)))
       (declare (type integer x y z))
       (let* ((zinv (if (= z 0) 0 (modular-inverse z (curve-order ,curve))))
	      (xx (mod (* x zinv) (curve-order ,curve)))
	      (yy (mod (* y zinv) (curve-order ,curve))))
	 (declare (type integer xx yy))
	 (let ((result (every #'= (vector ,correct-x ,correct-y) (vector xx yy))))
	   (if result
	       (format t "test ~a correct~%" ,k)
	       (format t "test ~a failed.~%result was ~a~%affine form:~a~%correct result: ~a~%"
		       ,k (vector x y z) (vector xx yy) (vector ,correct-x ,correct-y))))))))

(defcurvetest +curve-secp256r1+ 1
  #x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
  #x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

(defcurvetest +curve-secp256r1+ 2
  #x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978
  #x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1)

(defcurvetest +curve-secp256r1+ 3
  #x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C
  #x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032)

(defcurvetest +curve-secp256r1+ 4
  #xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852
  #xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6)

(defcurvetest +curve-secp256r1+ 5
  #x51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED
  #xE0C17DA8904A727D8AE1BF36BF8A79260D012F00D4D80888D1D0BB44FDA16DA4)

(defcurvetest +curve-secp256r1+ 6
  #xB01A172A76A4602C92D3242CB897DDE3024C740DEBB215B4C6B0AAE93C2291A9
  #xE85C10743237DAD56FEC0E2DFBA703791C00F7701C7E16BDFD7C48538FC77FE2)

(defcurvetest +curve-secp256r1+ 7
  #x8E533B6FA0BF7B4625BB30667C01FB607EF9F8B8A80FEF5B300628703187B2A3
  #x73EB1DBDE03318366D069F83A6F5900053C73633CB041B21C55E1A86C1F400B4)

(defcurvetest +curve-secp256r1+ 8
  #x62D9779DBEE9B0534042742D3AB54CADC1D238980FCE97DBB4DD9DC1DB6FB393
  #xAD5ACCBD91E9D8244FF15D771167CEE0A2ED51F6BBE76A78DA540A6A0F09957E)

(defcurvetest +curve-secp256r1+ 9
  #xEA68D7B6FEDF0B71878938D51D71F8729E0ACB8C2C6DF8B3D79E8A4B90949EE0
  #x2A2744C972C9FCE787014A964A8EA0C84D714FEAA4DE823FE85A224A4DD048FA)

(defcurvetest +curve-secp256r1+ 10
  #xCEF66D6B2A3A993E591214D1EA223FB545CA6C471C48306E4C36069404C5723F
  #x878662A229AAAE906E123CDD9D3B4C10590DED29FE751EEECA34BBAA44AF0773)

(defcurvetest +curve-secp256r1+ 11
  #x3ED113B7883B4C590638379DB0C21CDA16742ED0255048BF433391D374BC21D1
  #x9099209ACCC4C8A224C843AFA4F4C68A090D04DA5E9889DAE2F8EEFCE82A3740)

(defcurvetest +curve-secp256r1+ 12
  #x741DD5BDA817D95E4626537320E5D55179983028B2F82C99D500C5EE8624E3C4
  #x0770B46A9C385FDC567383554887B1548EEB912C35BA5CA71995FF22CD4481D3)

(defcurvetest +curve-secp256r1+ 13
  #x177C837AE0AC495A61805DF2D85EE2FC792E284B65EAD58A98E15D9D46072C01
  #x63BB58CD4EBEA558A24091ADB40F4E7226EE14C3A1FB4DF39C43BBE2EFC7BFD8)

(defcurvetest +curve-secp256r1+ 14
  #x54E77A001C3862B97A76647F4336DF3CF126ACBE7A069C5E5709277324D2920B
  #xF599F1BB29F4317542121F8C05A2E7C37171EA77735090081BA7C82F60D0B375)

(defcurvetest +curve-secp256r1+ 15
  #xF0454DC6971ABAE7ADFB378999888265AE03AF92DE3A0EF163668C63E59B9D5F
  #xB5B93EE3592E2D1F4E6594E51F9643E62A3B21CE75B5FA3F47E59CDE0D034F36)

(defcurvetest +curve-secp256r1+ 16
  #x76A94D138A6B41858B821C629836315FCD28392EFF6CA038A5EB4787E1277C6E
  #xA985FE61341F260E6CB0A1B5E11E87208599A0040FC78BAA0E9DDD724B8C5110)

(defcurvetest +curve-secp256r1+ 17
  #x47776904C0F1CC3A9C0984B66F75301A5FA68678F0D64AF8BA1ABCE34738A73E
  #xAA005EE6B5B957286231856577648E8381B2804428D5733F32F787FF71F1FCDC)

(defcurvetest +curve-secp256r1+ 18
  #x1057E0AB5780F470DEFC9378D1C7C87437BB4C6F9EA55C63D936266DBD781FDA
  #xF6F1645A15CBE5DC9FA9B7DFD96EE5A7DCC11B5C5EF4F1F78D83B3393C6A45A2)

(defcurvetest +curve-secp256r1+ 19
  #xCB6D2861102C0C25CE39B7C17108C507782C452257884895C1FC7B74AB03ED83
  #x58D7614B24D9EF515C35E7100D6D6CE4A496716E30FA3E03E39150752BCECDAA)

(defcurvetest +curve-secp256r1+ 20
  #x83A01A9378395BAB9BCD6A0AD03CC56D56E6B19250465A94A234DC4C6B28DA9A
  #x76E49B6DE2F73234AE6A5EB9D612B75C9F2202BB6923F54FF8240AAA86F640B8)
