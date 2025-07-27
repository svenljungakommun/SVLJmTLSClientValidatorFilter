# ROADMAP – SVLJmTLSClientValidatorFilter

This document outlines upcoming features, planned improvements, and architectural goals for future releases of the `SVLJmTLSClientValidatorFilter`.

---

## ✅ Design Principle

Most new features will be **optional** and **disabled by default**.
They can be explicitly enabled via the `mtls-config.properties` file to ensure operational control and backward compatibility.

---

## ✅ Under Consideration (upcoming minor releases)

* [ ] **Offline CRL fallback (local cache)**
  *(Uses locally stored CRL files if online CRL endpoints are unreachable)*

* [ ] **KeyUsage bit enforcement**
  *(Blocks certificates lacking `digitalSignature` or with invalid key usage bitmask)*

* [ ] **Configuration validation at startup**
  *(Fails fast if required settings in `mtls-config.properties` are missing or malformed)*

* [ ] **JSON-formatted logging for SIEM/SOC**
  *(Emits structured validation logs in JSON format for monitoring and security operations)*

* [ ] **Structured `X-SVLJ-*` headers (Base64 format)**
  *(Exposes certificate metadata such as serial number, thumbprint, SAN etc. as Base64-encoded HTTP attributes)*

* [ ] **TLS cipher suite validation**
  *(Optionally rejects clients using insecure TLS cipher suites like 3DES, RC4, EXPORT-grade ciphers)*

---

## 📆 Tentative Release Targets

| Feature                                               | Target Version |
| ----------------------------------------------------- | -------------- |
| Offline CRL fallback                                  | 0.6            |
| KeyUsage bit enforcement                              | 0.7            |
| JSON-formatted logging for SIEM                       | 0.8            |
| Configuration validation at startup                   | 0.9            |
| TLS cipher suite validation                           | 1.0            |
| Code/parameter standardization                        | 1.1            |
| Harmonized version with SVLJmTLSClientValidatorModule | 1.x            |
| OCSP support                                          | x.x            |

---
