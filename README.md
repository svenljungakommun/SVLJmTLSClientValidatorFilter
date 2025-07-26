# SVLJmTLSClientValidatorFilter v0.3

**Mutual TLS (mTLS) enforcement filter for Apache Tomcat**  
Maintainer: Svenljunga kommun  

---

## Overview

`SVLJmTLSClientValidatorFilter` is a Java Servlet `Filter` that enforces mutual TLS (mTLS) client certificate validation in Tomcat-hosted web applications.

It validates client X.509 certificates against configurable trust policies, including issuer verification, certificate chain validation using a local CA bundle, signature algorithm and EKU enforcement, and optional thumbprint or serial number restrictions. Built for secure municipal and public sector infrastructure in Zero Trust architectures.

This filter is functionally equivalent to the official .NET module [`SVLJmTLSClientValidatorModule`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule) and mirrors its validation logic, configuration structure, and "fail-closed" enforcement model.

---

## Features

- 🔐 Strict mTLS enforcement on all incoming HTTPS requests
- ✅ Validation logic:
  - Ensures HTTPS and client certificate presence
  - Matches Issuer CN (`SVLJ_IssuerName`) using structured DN parsing
  - Validates chain against PEM bundle (`SVLJ_CABundlePath`)
  - Performs offline CRL check against trusted issuers
  - Validates NotBefore and NotAfter dates
  - Optional issuer thumbprint match (`SVLJ_IssuerThumbprint`)
  - Optional strict client certificate serial whitelist (`SVLJ_CertSerialNumbers`)
  - Optional thumbprint whitelist (`SVLJ_AllowedClientThumbprints`)
  - Optional signature algorithm validation (`SVLJ_AllowedSignatureAlgorithms`)
  - Optional EKU OID validation (`SVLJ_AllowedEKUOids`)
  - Optional IP-based bypass (`SVLJ_InternalBypassIPs`)
- 📤 Certificate attributes exposed as request attributes:
  - `X-SVLJ-SUBJECT`
  - `X-SVLJ-THUMBPRINT`
  - `X-SVLJ-ISSUER`
  - `X-SVLJ-SERIAL`
  - `X-SVLJ-VALIDFROM`
  - `X-SVLJ-VALIDTO`
  - `X-SVLJ-SIGNATUREALG`
- ⚙️ Configuration via `mtls-config.properties` in classpath
- 🚫 Fail-closed model: any untrusted client is redirected

---

## Directory Structure

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

````

---

## Example Configuration (`mtls-config.properties`)

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
````

---

## Enabling the Filter (`web.xml`)

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

## Enabling Client Certificate Negotiation in Tomcat

Ensure your Tomcat `server.xml` connector is configured for mutual TLS:

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
| `issuer-not-trusted`            | Issuer thumbprint does not match            |
| `crl-check-failed`              | Certificate not issued by trusted CA        |
| `cert-expired`                  | Client certificate is expired               |
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
