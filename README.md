# SVLJmTLSClientValidatorFilter v0.1

**Mutual TLS (mTLS) enforcement filter for Apache Tomcat**  
Maintainer: Svenljunga kommun  

---

## Overview

`SVLJmTLSClientValidatorFilter` is a Java Servlet `Filter` that enforces mutual TLS (mTLS) client certificate validation in Tomcat-hosted web applications.

It validates client X.509 certificates against configurable trust policies, including issuer verification, certificate chain validation using a local CA bundle, and optional thumbprint and signature algorithm enforcement. Built for secure municipal and public sector infrastructure in Zero Trust architectures.

This filter is based on the original .NET `IHttpModule` [`SVLJmTLSClientValidatorModule`](https://github.com/svenljungakommun/SVLJmTLSClientValidatorModule) for IIS, and mirrors its validation logic, configuration principles, and "fail-closed" enforcement model.

---

## Features

- 🔐 Strict mTLS enforcement on all incoming HTTPS requests
- ✅ Validation logic:
  - Ensures HTTPS and client certificate presence
  - Matches Issuer CN (`SVLJ_IssuerName`)
  - Validates chain against PEM bundle (`SVLJ_CABundlePath`)
  - Enforces NotBefore and NotAfter date validity
  - Optional issuer thumbprint (`SVLJ_IssuerThumbprint`)
  - Optional strict client certificate serial whitelist (`SVLJ_CertSerialNumbers`)
  - Optional IP whitelist/bypass (`SVLJ_InternalBypassIPs`)
  - Optional Signature Algorithm validation (`SVLJ_AllowedSignatureAlgorithms`)
  - Optional client certificate thumbprint validation (`SVLJ_AllowedClientThumbprints`)
- 📤 Certificate attributes exposed as request attributes:
  - `X-SVLJ-SUBJECT`
  - `X-SVLJ-THUMBPRINT`
  - `X-SVLJ-ISSUER`
  - `X-SVLJ-SERIAL`
  - `X-SVLJ-VALIDFROM`
  - `X-SVLJ-VALIDTO`
  - `X-SVLJ-SIGNATUREALG`
- ⚙️ Configuration via `mtls-config.properties` in classpath
- 🚫 Fail-closed design: unauthenticated clients are redirected

---

## Directory Structure

```

/opt/tomcat/webapps/mtls-app/
├── WEB-INF
│   ├── web.xml
│   └── classes
│       ├── svlj/security/SVLJmTLSClientValidatorFilter.class
│       └── mtls-config.properties
└── error
└── 403c.html
/opt/svlj/
└── ca-bundle.pem

````

---

## Example Configuration (`mtls-config.properties`)

```properties
SVLJ_IssuerName=SVLJ ADM Issuing CA v1
SVLJ_IssuerThumbprint=ABCDEF123456...
SVLJ_CABundlePath=/opt/svlj/ca-bundle.pem
SVLJ_ErrorRedirectUrl=/error/403c.html

SVLJ_CertSerialNumbers=12AB34CD56EF7890,ABCDE12345FEDCBA
SVLJ_InternalBypassIPs=127.0.0.1,10.0.0.5
SVLJ_AllowedSignatureAlgorithms=sha256withrsa,ecdsaWithSHA256
SVLJ_AllowedClientThumbprints=ABC123DEF456...,...
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

Ensure that the HTTPS connector in `server.xml` enables client authentication:

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true"
           keystoreFile="conf/keystore.p12" keystorePass="changeit" keystoreType="PKCS12"
           clientAuth="true"
           sslProtocol="TLS" />
```

---

## Error Handling

Unauthorized clients are redirected to:

```
/error/403c.html?reason=<code>
```

### Reason codes

| Code                            | Description                       |
| ------------------------------- | --------------------------------- |
| `missing-cert`                  | No certificate presented          |
| `issuer-name-mismatch`          | Issuer CN does not match          |
| `issuer-not-trusted`            | Issuer thumbprint mismatch        |
| `cert-expired`                  | Certificate is expired            |
| `cert-notyetvalid`              | Certificate is not yet valid      |
| `validation-error`              | Internal error during validation  |
| `serial-mismatch`               | Serial number mismatch            |
| `eku-missing`                   | EKU was required but none found   |
| `eku-not-allowed`               | EKU was required but none matched |
| `sigalg-not-allowed`            | Signature algorithm not allowed   |
| `client-thumbprint-not-allowed` | Client thumbprint mismatch        |
| `insecure-connection`           | Request was not made over HTTPS   |

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
