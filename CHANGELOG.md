# Changelog
All notable changes to this project will be documented in this file.


## [1.1.0] - 2023-05-13 Vicknesh Suppramaniam

### Added
- New function SetSalt() for users to set salt based on their preference.

### Modified
- Function Generate() generates a salt if none is given, as opposed to generating it during KDF init.
- Renamed return variable `hash` to `key`.


## [1.0.0] - 2023-05-12 Vicknesh Suppramaniam

### Added
- Initial code creation.