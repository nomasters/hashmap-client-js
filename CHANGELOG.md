# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2018-08-31
### Fixed
- fixed issue implimentation of `getBlake2b256MultiHash()` to properly hash and encode publicKey to to blake2b256 in multihash format. This was causing a false mismatch on the get request validating the URL to the payload.

## [0.1.0] - 2018-08-31
### Added
- added `setServerURI` and `getServerURI` functions to set global hashmap server defaults


## [0.0.2] - 2018-08-30
### Added
- integrated with ci and coverage tools
- added status badges
- added (this) CHANGELOG


## [0.0.1] - 2018-08-30
### Added
- initial commits of hashmap