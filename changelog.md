# 0.10.0

* Completely refactored API

* Added rev32 support

* Removed examples because they are difficult to maintain

# 0.9.2

* Added ability to export raw symmetric keys

# 0.9.1

* Enabled llvm flag support on executables

* Removed deepseq library dependency

* Disallowed reserved nonce (2^64 - 1)

* Fixed problem with CipherState count not incrementing

# 0.9.0

* Removed secondary key support (rev 31)

* Renamed dh tokens (rev 31)

* Added Noise-C vectors

* Regenerated test vectors

* Now using IsString instance of ScrubbedBytes from memory package

* Linting

# 0.8.0

* Exceptions are now provided by the safe-exceptions package
  (breaking API change)

* Added Noise\_XXfallback pattern

* Minor improvements to handshake pattern definition

* Updated non-standard handshake patterns to conform with rev 30

* Fixed bug which caused echo-server to read wrong public key

# 0.7.0

* Major API overhaul and refactoring

* Added test vector support

* Added secondary symmetric key support

* Added GHC 8.0.2 to unit tests

* Removed Noise\_XR

* General code cleanup and other minor tweaks

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
