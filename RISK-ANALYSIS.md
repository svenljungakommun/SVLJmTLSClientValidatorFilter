# RISK ANALYSIS – SVLJmTLSClientValidatorFilter

A structured threat and mitigation analysis

## 📚 Table of Contents

* [Introduction](#📚-introduction)
* [Protected Assets](#🔐-protected-assets)
* [Identified Risks](#⚠️-identified-risks)
* [Module Assessment (Post-Mitigation)](#🧪-module-assessment-post-mitigation)
* [Recommended Actions](#✅-recommended-actions)

---

## 📚 Introduction

The `SVLJmTLSClientValidatorFilter` protects web applications hosted in Apache Tomcat by enforcing strict client authentication using mutual TLS (mTLS). It performs X.509 client certificate validation using configurable trust anchors, checks for certificate presence, validity periods, and ensures issuer and signature algorithm compliance before the application is reached. Designed for Zero Trust environments and public-sector systems.

---

## 🔐 Protected Assets

| Asset                         | Type          | Protection Value |
| ----------------------------- | ------------- | ---------------- |
| Web application backend       | Service       | High             |
| User identity via client cert | Information   | High             |
| CA bundle in PEM format       | Configuration | High             |
| Servlet request metadata      | Metadata      | Medium           |
| `mtls-config.properties` file | Configuration | Medium           |

---

## ⚠️ Identified Risks

| Risk ID | Threat                                      | Consequence                           | Likelihood | Risk Level | Comment                                                    |
| ------: | ------------------------------------------- | ------------------------------------- | ---------- | ---------- | ---------------------------------------------------------- |
|      R1 | No actual CRL parsing or revocation logic   | Revoked certificates may be accepted  | Medium     | High       | PEM CA chain presence only is checked; no `X509CRL` loaded |
|      R2 | Incorrect or tampered CA bundle             | Broken trust chain                    | Low        | High       | PEM is trusted blindly if format is valid                  |
|      R3 | Incomplete issuer CN parsing                | False rejection or acceptance         | Low        | Medium     | Improved CN parser in 0.3 mitigates this                   |
|      R4 | No OCSP/CRL fallback for offline CA check   | Revoked certs may slip through        | Medium     | Medium     | No OCSP/CRL fetch or fallback implemented                  |
|      R5 | Lack of structured logging                  | Debugging and traceability is limited | Medium     | Medium     | No integration with syslog/SIEM or audit system            |
|      R6 | ClientAuth not enforced in `server.xml`     | Filter may never receive certificate  | Medium     | Medium     | Must be enforced at Tomcat connector level                 |
|      R7 | Thumbprint/Serial mismatch misconfiguration | Legit clients blocked                 | Medium     | Medium     | Manual entry error could block valid users                 |
|      R8 | Missing EKU check (if required)             | Certs used outside intended scope     | Low        | Medium     | Optional check – not enforced unless configured            |

---

## 🧪 Module Assessment (Post-Mitigation)

| Protection Feature             | Status  | Comment                                               |
| ------------------------------ | ------- | ----------------------------------------------------- |
| HTTPS requirement              | ✅ OK    | Redirects on non-secure requests                      |
| Certificate requirement        | ✅ OK    | Missing cert triggers redirect                        |
| Issuer CN strict match         | ✅ OK    | Uses parsed X.500 CN comparison (improved in 0.3)     |
| Issuer thumbprint matching     | ✅ OK    | Optional; uses SHA-1 comparison if configured         |
| Certificate NotBefore/NotAfter | ✅ OK    | Rejects expired or not-yet-valid certs                |
| EKU OID check                  | ✅ OK    | Optional – enforced if config present                 |
| Signature algorithm control    | ✅ OK    | Optional – SHA256+ preferred, enforced via config     |
| Client serial/TP whitelist     | ✅ OK    | Optional – enforced if config provided                |
| CA chain validation            | ✅ OK    | Addressed in version 0.4                              |
| CRL revocation validation      | ✅ OK    | Addressed in version 0.5                              |
| Configuration file integrity   | ⚠️ WARN | No schema or init-time validation of properties       |
| Logging                        | ⚠️ WARN | No built-in structured logging or auditing            |

---

## ✅ Recommended Actions

| Recommendation                                              | Priority | Justification                                        |
| ----------------------------------------------------------- | -------- | ---------------------------------------------------- |
| Add offline CRL parsing (`X509CRL` support)                 | High     | Enable fallback revocation checking of client certs  |
| Validate `mtls-config.properties` on startup                | Medium   | Prevent silent fallback or misconfiguration          |
| Add syslog/JSON logging support                             | Medium   | Improve auditability and traceability                |

---
