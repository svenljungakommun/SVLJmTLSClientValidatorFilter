# ROADMAP – SVLJmTLSClientValidatorFilter

This document outlines upcoming features, planned improvements, and architectural goals for future releases of the SVLJ mutual TLS validation filter.

---

## ✅ Design Note

All upcoming features will be **optional** and **disabled by default**.  
They can be enabled explicitly via the `mtls-config.properties` file to to maintain compatibility and operational control.

---

## ✅ Under Consideration (next minor releases)

- [ ] KeyUsage bit enforcement  
  _(Block certificates missing digitalSignature or with invalid bitmask)_

- [ ] Local fallback cache for CRL  
  _(Optional file-based cache if online revocation fails)_

- [ ] Configuration validation on startup  
  _(Fail-fast if required `appSettings` are missing or malformed)_

- [ ] JSON-formatted logging for SIEM/SOC  
  _(Emit validation results in structured format to logs or EventLog)_

- [ ] Structured `X-SVLJ-*` headers  
  _(Expose base64-encoded thumbprint, serial, SAN etc. in consistent format)_

- [ ] Cipher suite validation  
  _(Optional rejection of clients using insecure TLS ciphers like 3DES, RC4, export-grade suites)_

---

## 📆 Tentative Release Targets

| Feature                                               | Target Version |
|-------------------------------------------------------|----------------|
| KeyUsage bit enforcement                              | 1.4.6          |
| JSON-formatted logging                                | 1.4.7          |
| CRL local fallback / caching                          | 1.4.8          |
| Configuration validation                              | 1.4.9          |
| Cipher suite validation                               | 1.5.0          |
| Code & parameter cleanup and standardisation          | 1.5.1          |
| OCSP support                                          | x.x            |

