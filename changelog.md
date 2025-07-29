# Changelog – SVLJmTLSClientValidatorFilter

All notable changes to this module will be documented in this file.

This project adheres to a fail-closed Zero Trust model and is used in Apache Tomcat environments requiring mutual TLS authentication.

---

## [1.4.5] – 2025-07-29
`SVLJmTLSClientValidatorFilter` now fully harmonises with the latest version of `SVLJmTLSClientValidatorModule` and now has the same release version.

## [0.6] – 2025-07-28

### Added
- The filter now performs **complete validation of the entire client certificate chain**, from leaf certificate to a trusted CA root/intermediate.
- This is implemented via `CertPathValidator` using `PKIXParameters` and the CA bundle (`SVLJ_CABundlePath`) as trust anchors.
- This validation step is **strictly enforced** and cannot be bypassed or disabled.
- **Redirect reason on failure:** `issuer-not-trusted`.

### Changed
- The `doFilter()` method now uses the full chain (`X509Certificate[]`) obtained from the servlet request.
- The full chain is passed to the path validator instead of validating a single certificate.

## [0.5] – 2025-07-27

### Added
- **Online CRL validation** via HTTP/HTTPS using Distribution Points (OID 2.5.29.31)
  - Implemented method `isCertificateRevoked(X509Certificate cert)` using fail-closed model
  - Added `extractCrlUrls()` to parse CRL URLs from certificate extension
  - Introduced `downloadCRL()` with `HttpURLConnection` and CRL parsing

### Changed
- **Certificate chain validation** now explicitly separated from CRL checks

## [0.4] – 2025-07-26

### Added
- Certificate chain validation using `CertPathValidator` against the configured CA bundle.
  - Chain validation is mandatory and cannot be disabled.
  - Failure to validate the chain results in redirect with `issuer-not-trusted`.

### Changed
- Validation step order updated:
  - Chain validation is now performed before issuer thumbprint check.
  - Ensures consistency with .NET module (`SVLJmTLSClientValidatorModule`).


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
