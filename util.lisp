(in-package :tls)

(defun valid-content-p (content-type)
  (member
   content-type
   (list +RECORD-HANDSHAKE+
	 +RECORD-APPLICATION-DATA+
	 +RECORD-CHANGE-CIPHER-SPEC+
	 +RECORD-ALERT+
	 +RECORD-HEARTBEAT+)))

(defun valid-version-p (version)
  (member
   version
   (list +TLS-1.0+
	 +TLS-1.1+
	 +TLS-1.2+)))
