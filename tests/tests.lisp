(defpackage tls/tests
  (:use :cl :prove :alien-ring :tls))

(in-package :tls/tests)

(plan 3)

(defun test-reading-of-client-hellos ()
  (let* ((record1 "1603010188010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	 (client-hello1 (subseq record1 10))
	 (record2 "16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304")
	 (client-hello2 (subseq record2 10))
	 (recbuf (make-ring-buffer 8192))
	 (buf (make-ring-buffer 8192)))

    ;; write record to ring buffer
    (ring-buffer-write-byte-sequence recbuf (ironclad:hex-string-to-byte-array record2))

    (let ((tls::*mode* :CLIENT))
      (let* ((rec (tls::read-value 'tls::tls-record recbuf))
	     (class (tls::get-record-content-type rec))
	     (obj))
	;; read the record bytes and rewrite them into the tls buffer
	(ring-buffer-write-byte-sequence buf (ring-buffer-read-byte-sequence recbuf (tls::get-record-size rec)))
	(setf obj (tls::read-value class buf))
	(tls::write-value (type-of obj) buf obj)
	(is (ironclad:byte-array-to-hex-string (ring-buffer-read-byte-sequence buf)) client-hello2)))

    (ring-buffer-write-byte-sequence recbuf (ironclad:hex-string-to-byte-array record1))

    (let ((tls::*mode* :CLIENT))
      (let* ((rec (tls::read-value 'tls::tls-record recbuf))
	     (class (tls::get-record-content-type rec))
	     (obj))

	(ring-buffer-write-byte-sequence buf (ring-buffer-read-byte-sequence recbuf (tls::get-record-size rec)))
	(setf obj (tls::read-value class buf))
	(tls::write-value (type-of obj) buf obj)
	(is (ironclad:byte-array-to-hex-string (ring-buffer-read-byte-sequence buf)) client-hello1)))))

(defun test-reading-of-server-hellos ()
  (let* ((rec "160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304")
	 (server-hello (subseq rec 10))
	 (recbuf (make-ring-buffer 8192))
	 (tlsbuf (make-ring-buffer 8192)))

    (ring-buffer-write-byte-sequence recbuf (ironclad:hex-string-to-byte-array rec))

    (let ((tls::*mode* :SERVER))
      (let* ((rec (tls::read-value 'tls::tls-record recbuf))
	     (class (tls::get-record-content-type rec))
	     (obj))
	(ring-buffer-write-byte-sequence tlsbuf (ring-buffer-read-byte-sequence recbuf (tls::get-record-size rec)))
	(setf obj (tls::read-value class tlsbuf))
	(tls::write-value (type-of obj) tlsbuf obj)
	(is (ironclad:byte-array-to-hex-string (ring-buffer-read-byte-sequence tlsbuf)) server-hello)))))

(test-reading-of-client-hellos)
(test-reading-of-server-hellos)
(finalize)
