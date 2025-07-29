# SVLJmTLSClientValidatorFilter v1.4.5

**Mutual TLS (mTLS) enforcement filter for Apache Tomcat**

Maintainer: Svenljunga kommun

---

## Overview

`SVLJmTLSClientValidatorFilter` is a Java Servlet `Filter` that enforces mutual TLS (mTLS) client certificate validation in Tomcat-hosted web applications.

It validates client X.509 certificates against configurable trust policies, including issuer verification, certificate chain validation using a local CA bundle, CRL checks, signature algorithm and EKU enforcement, and optional thumbprint or serial number restrictions.
Built for secure public sector and critical infrastructure in Zero Trust architectures.

This filter is functionally equivalent to the .NET module [`SVLJmTLSClientValidatorModule`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule) and mirrors its validation logic, configuration structure, and "fail-closed" enforcement model.

---

## Features

* 🔐 Strict mTLS enforcement on all incoming HTTPS requests
* ✅ Validation logic:

  * Ensures HTTPS and client certificate presence
  * Matches Issuer CN (`SVLJ_IssuerName`) using structured DN parsing
  * Validates certificate chain against PEM CA bundle (`SVLJ_CABundlePath`)
  * Checks CRL Distribution Points (CDP) over HTTP/HTTPS (fail-closed)
  * Validates NotBefore and NotAfter dates
  * Optional issuer thumbprint match (`SVLJ_IssuerThumbprint`)
  * Optional strict client certificate serial whitelist (`SVLJ_CertSerialNumbers`)
  * Optional thumbprint whitelist (`SVLJ_AllowedClientThumbprints`)
  * Optional signature algorithm validation (`SVLJ_AllowedSignatureAlgorithms`)
  * Optional EKU OID validation (`SVLJ_AllowedEKUOids`)
  * Optional IP-based bypass (`SVLJ_InternalBypassIPs`)
* 📤 Certificate attributes exposed as request attributes:
  * `X-SVLJ-SUBJECT`
  * `X-SVLJ-THUMBPRINT`
  * `X-SVLJ-ISSUER`
  * `X-SVLJ-SERIAL`
  * `X-SVLJ-VALIDFROM`
  * `X-SVLJ-VALIDTO`
  * `X-SVLJ-SIGNATUREALG`
 
* ⚙️ Configuration via `mtls-config.properties` in classpath
* 🚫 Fail-closed model: any untrusted client is redirected

---

## Compliance Alignment

This module supports security controls required by:

- **NIS2 Directive**
- **ISO/IEC 27001 & 27002**
- **GDPR (Art. 32 – Security of processing)**
- **CIS Benchmarks**
- **STIGs (US DoD)**

---

## Requirements

* **Java 11+**
* **Apache Tomcat 10+** (supports `jakarta.servlet.*`)
* **PEM-formatted CA bundle** for trust validation (`SVLJ_CABundlePath`)
* **CRL Distribution Points (CDP)** must be accessible via HTTP/HTTPS if CRL is used

---

## Dependencies

All used classes are part of the standard Java SDK and Jakarta EE:

| Component            | Package / Class              | Notes                  |
| -------------------- | ---------------------------- | ---------------------- |
| Servlet Filter       | `jakarta.servlet.*`          | Provided by Tomcat 10+ |
| Certificate handling | `java.security.cert.*`       | Included in JDK        |
| CRL and Thumbprint   | `java.security.*`            | Included in JDK        |
| DN parsing (CN)      | `javax.naming.ldap.*`        | Included in JDK        |
| CRL download (HTTP)  | `java.net.HttpURLConnection` | Included in JDK        |

> ✅ No third-party dependencies or libraries required.

> ⚠️ Tomcat versions prior to 10.x needs to be built using javax.*

---

## Installation & Configuration

### Directory Structure

```
/opt/tomcat/webapps/mtls-app/
├── WEB-INF
│   ├── web.xml
│   └── classes
│       ├── svlj/security/SVLJmTLSClientValidatorFilter.class
│       └── mtls-config.properties
└── error/
└── 403c.html

/opt/svlj/
└── ca-bundle.pem
```

---

### `mtls-config.properties` (Classpath)

```properties
SVLJ_IssuerName=Some CA
SVLJ_IssuerThumbprint=ABCDEF123456...
SVLJ_CABundlePath=/opt/svlj/ca-bundle.pem
SVLJ_ErrorRedirectUrl=/error/403c.html

SVLJ_CertSerialNumbers=12AB34CD56EF7890,ABCDE12345FEDCBA
SVLJ_InternalBypassIPs=127.0.0.1,10.0.0.5
SVLJ_AllowedSignatureAlgorithms=sha256withrsa,ecdsaWithSHA256
SVLJ_AllowedClientThumbprints=ABC123DEF456...
SVLJ_AllowedEKUOids=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1
```

---

### `web.xml` Configuration

```xml
<filter>
  <filter-name>SVLJmTLSValidator</filter-name>
  <filter-class>svlj.security.SVLJmTLSClientValidatorFilter</filter-class>
</filter>

<filter-mapping>
  <filter-name>SVLJmTLSValidator</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

---

### Tomcat Connector Configuration

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true"
           keystoreFile="conf/keystore.p12" keystorePass="changeit" keystoreType="PKCS12"
           clientAuth="true"
           sslProtocol="TLS" />
```

---

## Error Handling

Unauthorized or misconfigured clients are redirected to:

```
/error/403c.html?reason=<code>
```

### Reason Codes

| Code                            | Description                                 |
| ------------------------------- | ------------------------------------------- |
| `missing-cert`                  | No certificate presented                    |
| `issuer-name-mismatch`          | Issuer CN does not match expected CN        |
| `issuer-not-trusted`            | Certificate chain or thumbprint invalid     |
| `crl-check-failed`              | CRL check failed or certificate revoked     |
| `expired-cert`                  | Client certificate is expired               |
| `cert-notyetvalid`              | Client certificate is not yet valid         |
| `serial-mismatch`               | Serial number not in allowed list           |
| `eku-missing`                   | No EKU present when EKU required            |
| `eku-not-allowed`               | EKU does not match any allowed OIDs         |
| `sigalg-not-allowed`            | Signature algorithm not in allowed list     |
| `client-thumbprint-not-allowed` | Client thumbprint does not match            |
| `insecure-connection`           | Request was made over non-HTTPS             |
| `validation-error`              | Internal certificate parsing or logic error |

---

## Testing

### PowerShell

```powershell
Invoke-WebRequest -Uri "https://your-app" -Certificate (Get-Item Cert:\CurrentUser\My\<THUMBPRINT>)
```

### OpenSSL

```bash
openssl s_client -connect your-app:443 -cert client.crt -key client.key -CAfile ca-bundle.pem
```

### Curl

```bash
curl --cert client.crt --key client.key https://your-app
```
