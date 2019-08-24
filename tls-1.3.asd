(defsystem tls-1.3
  :version "0.1.0"
  :author "Mateusz Berezecki"
  :license "BSD"
  :depends-on
  ("ironclad"
   "alien-ring")
  :components ((:file "packages")
	       (:file "constants" :depends-on ("packages"))
	       (:file "context" :depends-on ("packages"))
	       (:file "serialization" :depends-on ("packages"))
	       (:file "tls" :depends-on ("serialization"))
	       (:file "handshake" :depends-on ("serialization"))
	       (:file "record" :depends-on ("packages")))
  :in-order-to ((test-op (test-op "tls-1.3/test")))
  :description "A lightweight minimal tls1.3 library that is easy to integrate.")

(defsystem "tls-1.3/test"
  :depends-on ("prove")
  :defsystem-depends-on (:prove-asdf)
  :serial t
  :components ((:module "tests" :components ((:test-file "tests"))))
  :perform (test-op :after (o c)
		    (funcall (intern #. (string :run) :prove) c)))
