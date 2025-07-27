# SVLJmTLSClientValidatorFilter Code Validation
Updated: 2025-07-27 for version 0.5

### ✅ **Tomcat Filter Integration**

| Aspect                                                               | Status | Notes                                               |
| -------------------------------------------------------------------- | ------ | --------------------------------------------------- |
| Declares `implements Filter`                                         | ✅      | Class implements `jakarta.servlet.Filter` correctly |
| `init()` method present                                              | ✅      | Loads configuration and CA bundle                   |
| `doFilter()` implementation                                          | ✅      | Core logic with full validation pipeline            |
| `destroy()` implemented                                              | ✅      | Present (no cleanup logic required)                 |
| Uses `jakarta.servlet.*`                                             | ✅      | Required for Tomcat 10+ compatibility               |
| Certificate from attribute `jakarta.servlet.request.X509Certificate` | ✅      | Standard mTLS attribute in Servlet API              |

---

### ✅ **Fail-Closed Validation Pipeline**

Every check in `doFilter()` is fail-closed. That means:

* If validation **fails**, it **never** allows the request to proceed.
* Instead, it issues a **302 redirect** to `errorRedirect + "?reason=..."`.

| Step                            | Condition                                        | Reason String                   | Status               |             
| ------------------------------- | ------------------------------------------------ | ------------------------------- | -------------------- | 
| HTTPS required                  | `!req.isSecure()`                                | `insecure-connection`           | ✅                   |               
| No client certificate           | \`certs == null                                  | `missing-cert`                  | ✅                   |
| Invalid Issuer CN               | `!issuerCN.equalsIgnoreCase(...)`                | `issuer-name-mismatch`          | ✅                   |               
| Chain validation failed         | `!validateCertificateChain(...)`                 | `issuer-not-trusted`            | ✅                   |              
| CRL revoked OR fetch fails      | `isCertificateRevokedOnline(...)` returns `true` | `crl-check-failed`              | ✅                   |             
| Issuer thumbprint mismatch      | no match in trusted issuers                      | `issuer-not-trusted`            | ✅                   |                
| Certificate expired             | `clientCert.getNotAfter().before(new Date())`    | `expired-cert`                  | ✅                   |                
| Certificate not yet valid       | `clientCert.getNotBefore().after(new Date())`    | `cert-notyetvalid`              | ✅                   |                
| Serial not allowed              | not in `allowedSerials`                          | `serial-mismatch`               | ✅                   |            
| EKU missing                     | \`ekuList == null                                | `eku-missing`                   | ✅                   |
| EKU not allowed                 | no match in `allowedEKUOids`                     | `eku-not-allowed`               | ✅                   |                
| Signature algorithm not allowed | not in `allowedSignatureAlgs`                    | `sigalg-not-allowed`            | ✅                   |             
| Thumbprint not allowed          | not in `allowedThumbprints`                      | `client-thumbprint-not-allowed` | ✅                   |              
| Certificate parsing error       | thrown in try block                              | `validation-error`              | ✅                   | 

---

### ✅ **CRL Behavior**

* Uses HTTP(S) only
* `conn.setUseCaches(false)` ensures freshness
* All **fetch errors**, **parsing errors**, and **extraction failures** → `crl-check-failed` via redirect
* CRL check logic is **inline, hardcoded**, not bypassable

---

### ✅ **Bypass & Exception Handling**

| Bypass              | Condition                                       | Status                                 |
| ------------------- | ----------------------------------------------- | -------------------------------------- |
| `/error` path       | URI starts with `/error`                        | ✅ Skipped for redirect loop protection |
| Internal IP         | IP in `SVLJ_InternalBypassIPs`                  | ✅ Full bypass                          |
| All redirect causes | Handled via `redirect(...)` → 302 + `Location:` | ✅                                      |

---

### ✅ **Filter Safety**

* No external dependencies
* No unhandled exceptions (all caught or rethrown as ServletException)
* Fails safely under:

  * Missing config keys
  * Missing CA file
  * Invalid certificate structure

---

### ✅ **Conclusion**

✅ The filter is **fully valid and production-safe** for use in Tomcat 10+.

Every *soft-fail* or *validation error* results in a strict `302` redirect to the defined error URL (`errorRedirect`), with a `?reason=...` code matching the exact failure.
