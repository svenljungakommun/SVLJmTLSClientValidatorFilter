# Changelog – SVLJmTLSClientValidatorFilter

All notable changes to this project are documented in this file.  

---

## [0.3] – 2025-07-26

### Added
- **Issuer thumbprint validation** (`SVLJ_IssuerThumbprint`) against CA bundle
- **Client certificate thumbprint validation** (`SVLJ_AllowedClientThumbprints`)
- **Signature algorithm enforcement** (`SVLJ_AllowedSignatureAlgorithms`)
- **Extended Key Usage (EKU) enforcement** (`SVLJ_AllowedEKUOids`)
- **CRL trust checking** via presence of issuer in trusted CA bundle (basic offline)
- **Structured Issuer CN parsing** via `LdapName` → replaces previous `contains("CN=...")`

### Changed
- All validation and redirect logic moved under unified `try/catch` block in `doFilter()`
- Cleaned and hardened thumbprint generation (`safeThumbprint()`)
- Improved configuration parsing logic with consistent normalization (serials, thumbprints, algorithms, IPs)
- Refactored and documented all helper methods (PEM loader, parser, splitter)
- Code now adheres to consistent style, fail-closed policy and is production-ready


## [0.2] – 2025-07-25
Note: Version 0.2 was an internal development milestone and was never officially released.
It served as a transitional build used to prototype EKU validation and refactor the validation logic.

## [0.1] – 2025-07-24
Initial Java implementation of the mTLS validation filter, ported from the .NET-based SVLJmTLSClientValidatorModule.
