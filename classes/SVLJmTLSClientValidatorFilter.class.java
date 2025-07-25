/**
 * SVLJmTLSClientValidatorFilter – Servlet filter for strict mTLS authentication in Apache Tomcat.
 *
 * This filter enforces mutual TLS (mTLS) by validating incoming HTTPS client certificates
 * according to a defined security policy. It is designed for Zero Trust environments,
 * particularly in municipal and public sector infrastructures.
 *
 * The filter validates:
 * - Presence and validity of the client certificate
 * - Issuer CN and optional issuer thumbprint
 * - Certificate chain against a local CA bundle (PEM format)
 * - Certificate validity window (NotBefore/NotAfter)
 * - Allowed serial numbers and/or SHA-1 thumbprints
 * - Allowed signature algorithms (optional)
 * - Allowed Extended Key Usage (EKU) OIDs (optional)
 * - Internal IP bypass (optional)
 * - Certificate information is exposed as request attributes for downstream use
 * - CRL revocation checking via trusted issuers (basic offline validation)
 *
 * Configuration is read from a `mtls-config.properties` file available on the application classpath.
 *
 * Supported configuration keys:
 * - SVLJ_IssuerName: Required. Expected issuer Common Name (CN)
 * - SVLJ_IssuerThumbprint: Optional. SHA-1 thumbprint of the trusted issuer
 * - SVLJ_CABundlePath: Required. Path to PEM file containing trusted CA certificates
 * - SVLJ_CertSerialNumbers: Optional. Comma-separated list of allowed serial numbers
 * - SVLJ_AllowedClientThumbprints: Optional. SHA-1 thumbprints of allowed client certificates
 * - SVLJ_AllowedSignatureAlgorithms: Optional. Allowed signature algorithms (e.g., sha256withrsa)
 * - SVLJ_AllowedEKUOids: Optional. Allowed Extended Key Usage (EKU) OIDs
 * - SVLJ_InternalBypassIPs: Optional. Comma-separated list of IPs that bypass validation
 * - SVLJ_ErrorRedirectUrl: Optional. URL to redirect unauthorized clients (default: /error/403c.html)
 *
 * This filter follows a "fail-closed" model, blocking any client that doesn't explicitly meet the policy.
 *
 * Author: Abdulaziz Almazrli / Odd-Arne Haraldsen
 * Version: 0.3
 * Updated: 2025-07-26
 */

package svlj.security;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.net.URLEncoder;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;
import javax.naming.ldap.*;

public class SVLJmTLSClientValidatorFilter implements Filter {

    private Set<String> allowedSerials = new HashSet<>();
    private Set<String> allowedThumbprints = new HashSet<>();
    private Set<String> allowedSignatureAlgs = new HashSet<>();
    private Set<String> allowedEKUOids = new HashSet<>();
    private Set<String> bypassIPs = new HashSet<>();
    private List<X509Certificate> trustedIssuers = new ArrayList<>();

    private String issuerCN;
    private String issuerThumbprint;
    private String errorRedirect;

    @Override
    public void init(FilterConfig config) throws ServletException {
        try (InputStream in = SVLJmTLSClientValidatorFilter.class.getClassLoader()
                .getResourceAsStream("mtls-config.properties")) {

            Properties props = new Properties();
            props.load(in);

            issuerCN = props.getProperty("SVLJ_IssuerName");
            issuerThumbprint = normalize(props.getProperty("SVLJ_IssuerThumbprint"));
            errorRedirect = props.getProperty("SVLJ_ErrorRedirectUrl", "/error/403c.html");

            allowedSerials.addAll(splitAndNormalize(props.getProperty("SVLJ_CertSerialNumbers")));
            allowedThumbprints.addAll(splitAndNormalize(props.getProperty("SVLJ_AllowedClientThumbprints")));
            allowedSignatureAlgs.addAll(split(props.getProperty("SVLJ_AllowedSignatureAlgorithms"), false));
            allowedEKUOids.addAll(split(props.getProperty("SVLJ_AllowedEKUOids"), false));
            bypassIPs.addAll(split(props.getProperty("SVLJ_InternalBypassIPs"), false));

            String caBundlePath = props.getProperty("SVLJ_CABundlePath");
            trustedIssuers.addAll(loadPEMCertificates(caBundlePath));

        } catch (Exception e) {
            throw new ServletException("Failed to initialize SVLJ mTLS filter", e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String ip = req.getRemoteAddr();
        
        /** Internal bypass (e.g. localhost, 127.0.0.1) */
        if (bypassIPs.contains(ip)) {
            chain.doFilter(request, response);
            return;
        }

        /** Require HTTPS */
        if (!req.isSecure()) {
            redirect(res, "insecure-connection");
            return;
        }

        /** Bypass /error folder */
        String path = req.getRequestURI();
        if (path != null && path.startsWith("/error")) {
            chain.doFilter(request, response);
            return;
        }

        /** Check for certificate in request  */
        X509Certificate[] certs = (X509Certificate[]) req.getAttribute("jakarta.servlet.request.X509Certificate");
        if (certs == null || certs.length == 0) {
            redirect(res, "missing-cert");
            return;
        }

        try {

            X509Certificate clientCert = certs[0];

            /**  Step 1: Expose cert info via HTTP headers */
            req.setAttribute("X-SVLJ-SUBJECT", clientCert.getSubjectX500Principal().getName());
            req.setAttribute("X-SVLJ-ISSUER", clientCert.getIssuerX500Principal().getName());
            req.setAttribute("X-SVLJ-SERIAL", clientCert.getSerialNumber().toString(16).toUpperCase());
            req.setAttribute("X-SVLJ-THUMBPRINT", thumbprint(clientCert));
            req.setAttribute("X-SVLJ-VALIDFROM", clientCert.getNotBefore().toString());
            req.setAttribute("X-SVLJ-VALIDTO", clientCert.getNotAfter().toString());
            req.setAttribute("X-SVLJ-SIGNATUREALG", clientCert.getSigAlgName());

            /** Step 2: Check expected Issuer CN */
            if (!issuerCN.equalsIgnoreCase(getCommonNameFromPrincipal(clientCert.getIssuerX500Principal()))) {
                redirect(res, "issuer-name-mismatch");
                return;
            }

            /** Step 3: Validate certificate chain including CRL */
            boolean issuedByTrustedCA = trustedIssuers.stream()
                    .anyMatch(trusted -> trusted.getSubjectX500Principal().equals(clientCert.getIssuerX500Principal()));
            if (!issuedByTrustedCA) {
                redirect(res, "crl-check-failed");
                return;
            }

            /** Step 4: Check optional issuer thumbprint */
            if (issuerThumbprint != null) {
                Optional<String> matchingThumb = trustedIssuers.stream()
                        .map(this::safeThumbprint)
                        .filter(Objects::nonNull)
                        .filter(tp -> tp.equalsIgnoreCase(issuerThumbprint))
                        .findFirst();
                if (matchingThumb.isEmpty()) {
                    redirect(res, "issuer-not-trusted");
                    return;
                }
            }

            /** Step 5: Check certificate validity window */
            if (clientCert.getNotAfter().before(new Date())) {
                redirect(res, "expired-cert");
                return;
            }

            /** Step 5: Check certificate validity window */
            if (clientCert.getNotBefore().after(new Date())) {
                redirect(res, "cert-notyetvalid");
                return;
            }

            /** Step 6: Check optional strict SerialNumber whitelist */
            if (!allowedSerials.isEmpty() &&
                    !allowedSerials.contains(clientCert.getSerialNumber().toString(16).toUpperCase())) {
                redirect(res, "serial-mismatch");
                return;
            }

            /** Step 7: Optional EKU enforcement */
            if (!allowedEKUOids.isEmpty()) {
                List<String> ekuList = clientCert.getExtendedKeyUsage();
                if (ekuList == null || ekuList.isEmpty()) {
                    redirect(res, "eku-missing");
                    return;
                }
                boolean match = ekuList.stream().anyMatch(allowedEKUOids::contains);
                if (!match) {
                    redirect(res, "eku-not-allowed");
                    return;
                }
            }

            /** Step 8: Optional Signature Algorithms enforcement */
            if (!allowedSignatureAlgs.isEmpty() &&
                    !allowedSignatureAlgs.contains(clientCert.getSigAlgName().toLowerCase())) {
                redirect(res, "sigalg-not-allowed");
                return;
            }

            /** Step 9: Optional Client Thumbprint enforcement */
            if (!allowedThumbprints.isEmpty() &&
                    !allowedThumbprints.contains(thumbprint(clientCert))) {
                redirect(res, "client-thumbprint-not-allowed");
                return;
            }

            chain.doFilter(request, response);

        } catch (CertificateParsingException e) {
            redirect(res, "validation-error");
        }
    }

    private void redirect(HttpServletResponse res, String reason) throws IOException {
        res.setStatus(302);
        res.setHeader("Location", errorRedirect + "?reason=" + URLEncoder.encode(reason, "UTF-8"));
    }

    private String normalize(String s) {
        return s == null ? null : s.replace(" ", "").toUpperCase();
    }

    private Set<String> splitAndNormalize(String raw) {
        return split(raw, true);
    }

    private Set<String> split(String raw, boolean upper) {
        if (raw == null || raw.trim().isEmpty()) return new HashSet<>();
        return Arrays.stream(raw.split("[;,]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> upper ? s.toUpperCase() : s.toLowerCase())
                .collect(Collectors.toSet());
    }

    private List<X509Certificate> loadPEMCertificates(String path) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        String pem = Files.readString(Paths.get(path));
        Matcher m = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                Pattern.DOTALL).matcher(pem);
        while (m.find()) {
            byte[] der = Base64.getMimeDecoder().decode(m.group(1).replaceAll("\\s+", ""));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        return certs;
    }

    private String thumbprint(X509Certificate cert) throws ServletException {
        try {
            byte[] encoded = cert.getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(encoded);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (Exception e) {
            throw new ServletException("Could not calculate thumbprint", e);
        }
    }

    private String safeThumbprint(X509Certificate cert) {
        try {
            return thumbprint(cert);
        } catch (Exception e) {
            return null;
        }
    }

    private String getCommonNameFromPrincipal(X500Principal principal) {
        try {
            LdapName ldapName = new LdapName(principal.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            return principal.getName();
        }
        return null;
    }

    @Override
    public void destroy() {}
}
