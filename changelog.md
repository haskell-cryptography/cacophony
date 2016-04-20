# 0.7.0

* Major API overhaul and refactoring

* Added test vector support

# 0.6.0

* Added ability to abort handshakes based on the remote party's public key

* Improved documentation

* Factored out ScrubbedBytes utilities to separate module

* Added echo-server and echo-client example

* Renamed HandshakeStateParams to HandshakeOpts

# 0.5.0

* Added Curve448 support

* Major refactoring and API changes
  A DSL was created to represent handshake patterns.

* Added GHC 7.10.3 to unit tests

# 0.4.0

* Improved documentation

* Added basic benchmarks

* Added better exception handling

* Improved handshakeState API

* Added psk2 functionality

* Unit test cleanup

* Renamed symmetricHandshake to symmetricState

* Added BLAKE2, SHA512, AESGCM support

# 0.3.0

* Brought API up to date with current version of spec (17)

# 0.2.0

* Added support for one-way handshakes

* Fixed Noise\_IX

* Added helper functions for ScrubbedBytes / ByteString conversion

# 0.1.0.0

* First version.
