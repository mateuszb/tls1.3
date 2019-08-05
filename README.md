<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [Overview](#overview)

<!-- markdown-toc end -->

# Overview

TLS 1.3 is a minimal common lisp implementation of the TLS1.3 specification that doesn't require
external dependencies and uses sane defaults from the TLS1.3 RFC. It does not try to be complete
but minimal required to limit the scope of the project and its complexity.

## Required extensions
TLS 1.3 RFC requires following extensions:
- **supported_versions** required for **ClientHello** and **ServerHello** messages
- **signature_algorithms** required for certificate authentication
- **supported_groups** required for **ClientHello** messages when using DHE or ECDHE key exchange
- **pre_shared_key** required for PSK agreement
- **psk_key_exchange_modes** required for PSK exchange

## Notes on protocol

TLS communicates using protocol messages and encapsulates them in the record layer wrappers.
Record layer wrappers are simply message headers that describe the content type and the 
protocol message length.


extension-type is 2 bytes

a list of extensions with N elements occupies 2 bytes + N * (2 bytes + size of the extension)

therefore a minimum TLS1.3 extension list with only supported-versions extensions being present occupies

2 bytes - extension list length
2 bytes - extension type
1 byte  - keep the length of the list of supported versions (in bytes)
2 bytes - supported version itself

0005
002b
