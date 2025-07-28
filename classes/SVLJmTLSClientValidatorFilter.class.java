/**
 * SVLJmTLSClientValidatorFilter – Servlet filter for strict mTLS authentication in Apache Tomcat.
 *
 * This filter enforces mutual TLS (mTLS) by validating incoming HTTPS client certificates
 * according to a strict and configurable security policy. It is designed for Zero Trust environments,
 * with specific application in municipal, critical infrastructure, and public sector systems.
 *
 * === Validation Capabilities ===
 * - Enforces HTTPS and requires a valid client certificate (mTLS)
 * - Validates that the issuer CN matches a configured expected value
 * - Optionally validates issuer SHA-1 thumbprint
 * - Validates the certificate chain against a local CA bundle (PEM format)
 * - Performs certificate revocation checking via CRL (over HTTP/HTTPS only)
 * - Validates NotBefore and NotAfter (certificate validity window)
 * - Optionally enforces whitelisted serial numbers
 * - Optionally enforces SHA-1 thumbprint matching for allowed client certificates
 * - Optionally enforces allowed signature algorithms (e.g., sha256withrsa)
 * - Optionally enforces one or more allowed Extended Key Usage (EKU) OIDs
 * - Optionally allows IP-based bypass for internal trusted sources
 * - Exposes certificate metadata as request attributes for downstream access
 *
 * === Configuration ===
 * Configuration is loaded from a `mtls-config.properties` file located in the application classpath.
 * 
 * Supported configuration keys:
 * - SVLJ_IssuerName                – Required. Expected issuer Common Name (CN)
 * - SVLJ_IssuerThumbprint          – Optional. SHA-1 thumbprint of the issuer certificate
 * - SVLJ_CABundlePath              – Required. Absolute path to a PEM file containing trusted CA certificates
 * - SVLJ_CertSerialNumbers         – Optional. Comma- or semicolon-separated list of allowed certificate serial numbers (hex)
 * - SVLJ_AllowedClientThumbprints  – Optional. List of allowed SHA-1 thumbprints of client certificates
 * - SVLJ_AllowedSignatureAlgorithms– Optional. List of allowed signature algorithms (e.g., sha256withrsa)
 * - SVLJ_AllowedEKUOids            – Optional. List of allowed Extended Key Usage OIDs
 * - SVLJ_InternalBypassIPs         – Optional. List of internal IP addresses allowed to bypass validation
 * - SVLJ_ErrorRedirectUrl          – Optional. Relative or absolute URL to redirect on validation failure (default: /error/403c.html)
 *
 * === Redirect Model ===
 * All validation failures cause an HTTP 302 redirect to the error URL with a query string:
 *     ?reason=<failure-cause>
 * 
 * Example reasons include:
 *     insecure-connection, missing-cert, issuer-name-mismatch, issuer-not-trusted,
 *     crl-check-failed, expired-cert, cert-notyetvalid, serial-mismatch,
 *     eku-missing, eku-not-allowed, sigalg-not-allowed, client-thumbprint-not-allowed,
 *     validation-error
 *
 * === Dependencies ===
 * - Java SE 11+ (or compatible)
 * - Apache Tomcat 10+ (requires Jakarta Servlet API)
 * - Jakarta Servlet API 5.0+ (`jakarta.servlet.*`)
 * - No external cryptographic or ASN.1 libraries (pure JDK implementation)
 * 
 * === Requirements ===
 * - Application must be served over HTTPS with client certificate authentication enabled in Tomcat (`clientAuth="true"`)
 * - CA certificates must be provided in PEM format
 * - CRLs must be accessible via HTTP or HTTPS (LDAP not supported)
 * - Jakarta-compatible deployment (post-Tomcat 10) required
 *
 * This filter follows a strict **fail-closed** model: any deviation from expected values results in denial of access.
 *
 * Author: Abdulaziz Almazrli / Odd-Arne Haraldsen  
 * Version: 0.6
 * Updated: 2025-07-28
 */

/** Namespace */
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

/** SVLJmTLSClientValidatorFilter  */
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
	/**
	 * Initializes the filter by loading configuration from the `mtls-config.properties` file.
	 *
	 * This method is called once when the filter is first created by the servlet container.
	 * It reads all policy parameters used for mTLS validation.
	 *
	 * The CA certificates from the specified PEM bundle are parsed and stored for use in
	 * certificate chain validation.
	 *
	 * @param config The filter configuration provided by the container
	 * @throws ServletException If the configuration is missing or cannot be parsed
	 */
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
	/**
	 * Core method that intercepts every HTTP(S) request and enforces mutual TLS (mTLS) authentication.
	 *
	 * This method is invoked for every incoming request. 
	 *
	 * If all checks pass, the request continues through the filter chain. Otherwise,
	 * the client is redirected to the configured error page with an appropriate `reason` code.
	 *
	 * @param request  The incoming ServletRequest (cast to HttpServletRequest)
	 * @param response The ServletResponse (cast to HttpServletResponse)
	 * @param chain    The FilterChain used to invoke the next filter or servlet
	 * @throws IOException      If an input or output error occurs
	 * @throws ServletException If an error occurs during processing
	 */
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

            /**  Step 1: Expose cert info via HTTP headers */
			X509Certificate clientCert = certs[0];
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

            /** Step 3: Validate certificate chain against trusted CA bundle */
            if (!validateCertificateChain(certs, trustedIssuers)) {
		redirect(res, "issuer-not-trusted");
		return;
            }
	
            /** Step 4: Validate certificate revocation using CDP/CRL over http/https */
            if (isCertificateRevoked(clientCert)) {
		redirect(res, "crl-check-failed");
		return;
            }

            /** Step 5: Check optional issuer thumbprint */
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

            /** Step 6: Check certificate validity window */
            if (clientCert.getNotAfter().before(new Date())) {
                redirect(res, "expired-cert");
                return;
            }

            /** Step 7: Check certificate validity window */
            if (clientCert.getNotBefore().after(new Date())) {
                redirect(res, "cert-notyetvalid");
                return;
            }

            /** Step 8: Check optional strict SerialNumber whitelist */
            if (!allowedSerials.isEmpty() &&
                    !allowedSerials.contains(clientCert.getSerialNumber().toString(16).toUpperCase())) {
                redirect(res, "serial-mismatch");
                return;
            }

            /** Step 9: Optional EKU enforcement */
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

            /** Step 10: Optional Signature Algorithms enforcement */
            if (!allowedSignatureAlgs.isEmpty() &&
                    !allowedSignatureAlgs.contains(clientCert.getSigAlgName().toLowerCase())) {
                redirect(res, "sigalg-not-allowed");
                return;
            }

            /** Step 11: Optional Client Thumbprint enforcement */
            if (!allowedThumbprints.isEmpty() &&
                    !allowedThumbprints.contains(thumbprint(clientCert))) {
                redirect(res, "client-thumbprint-not-allowed");
                return;
            }

            chain.doFilter(request, response);

		/** Validation failed: validation-error */
        } catch (CertificateParsingException e) {
            redirect(res, "validation-error");
        }
    }

	/**
	 * Issues an HTTP redirect (302 Found) to the configured error URL with a reason parameter.
	 *
	 * This method is used to terminate the request and inform the client of the specific
	 * validation failure by appending a `?reason=` query parameter to the error redirect URL.
	 * The reason is URL-encoded to ensure it is safely transmitted.
	 *
	 * Example:
	 *   If errorRedirect = "/error/403c.html" and reason = "expired-cert",
	 *   the client is redirected to: /error/403c.html?reason=expired-cert
	 *
	 * @param res    The HttpServletResponse object to send the redirect
	 * @param reason A short reason code describing the validation failure
	 * @throws IOException If writing the response fails
	 */
    private void redirect(HttpServletResponse res, String reason) throws IOException {
        res.setStatus(302);
        res.setHeader("Location", errorRedirect + "?reason=" + URLEncoder.encode(reason, "UTF-8"));
    }

	/**
	 * Normalizes a string by removing all spaces and converting it to uppercase.
	 *
	 * Returns null if the input is null. Otherwise, performs normalization to ensure
	 * consistent string comparison, particularly useful for thumbprints and identifiers.
	 *
	 * Example:
	 *   " ab 12 cd " ? "AB12CD"
	 *
	 * @param s The input string to normalize
	 * @return A space-free, uppercase version of the string, or null if input is null
	 */
    private String normalize(String s) {
        return s == null ? null : s.replace(" ", "").toUpperCase();
    }

	/**
	 * Convenience method for splitting a raw string into a Set of uppercase values.
	 *
	 * Internally delegates to `split(raw, true)`, meaning all resulting strings
	 * will be trimmed, filtered, and converted to uppercase.
	 *
	 * Used for configuration fields that require normalized matching,
	 * such as serial numbers or certificate thumbprints.
	 */
    private Set<String> splitAndNormalize(String raw) {
        return split(raw, true);
    }

	/**
	 * Splits a raw string into a Set of cleaned and optionally normalized values.
	 *
	 * This utility method is used to parse configuration values from comma- or semicolon-separated strings
	 * (e.g. certificate serials, thumbprints, IPs, algorithms).
	 *
	 * - Null or empty input returns an empty Set.
	 * - Trims each entry.
	 * - Filters out empty entries.
	 * - Applies case normalization:
	 *   - If `upper` is true, values are converted to uppercase.
	 *   - If `upper` is false, values are converted to lowercase.
	 *
	 * Example:
	 *   Input: "abc ; DEF,ghi ", upper=true ? Output: ["ABC", "DEF", "GHI"]
	 */
    private Set<String> split(String raw, boolean upper) {
        if (raw == null || raw.trim().isEmpty()) return new HashSet<>();
        return Arrays.stream(raw.split("[;,]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> upper ? s.toUpperCase() : s.toLowerCase())
                .collect(Collectors.toSet());
    }

	/**
	 * Loads one or more X.509 certificates from a PEM-formatted file.
	 *
	 * This method reads the entire contents of the specified file, extracts all embedded
	 * PEM certificates (delimited by "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"),
	 * decodes them from Base64 to DER format, and converts them into X509Certificate objects.
	 *
	 * It supports multiple certificates in the same file, such as CA bundles.
	 *
	 * @param path The filesystem path to the PEM-formatted certificate file
	 * @return A list of parsed X509Certificate objects
	 * @throws Exception If reading the file, decoding, or certificate parsing fails
	 */
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

	/**
	 * Calculates the SHA-1 thumbprint (hash) of an X.509 certificate.
	 *
	 * The thumbprint is commonly used to uniquely identify certificates and
	 * is represented as an uppercase hexadecimal string without delimiters.
	 * 
	 * This method:
	 * - Encodes the certificate to DER format
	 * - Hashes the byte array using SHA-1
	 * - Formats the resulting hash as an uppercase hex string
	 *
	 * @param cert The X509Certificate to hash
	 * @return The SHA-1 thumbprint as a hex string (e.g., "AB12CD34...")
	 * @throws ServletException If the encoding or hashing fails
	 */
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

	/**
	 * Safely calculates the SHA-1 thumbprint of the given X.509 certificate.
	 *
	 * This is a wrapper around the `thumbprint` method that suppresses any exceptions
	 * and returns `null` if thumbprint calculation fails.
	 *
	 * Useful in non-critical contexts (e.g., scanning issuer list) where a failed
	 * thumbprint shouldn't interrupt the validation flow.
	 *
	 * @param cert The X509Certificate to hash
	 * @return The thumbprint as a hex string, or null if an error occurs
	 */
    private String safeThumbprint(X509Certificate cert) {
        try {
            return thumbprint(cert);
        } catch (Exception e) {
            return null;
        }
    }

	/**
	 * Extracts the Common Name (CN) component from an X.500 principal (e.g., Issuer or Subject).
	 *
	 * This method parses the distinguished name using LDAP syntax and searches for the RDN
	 * (Relative Distinguished Name) with type "CN" (case-insensitive).
	 *
	 * If parsing fails, the full DN string is returned as a fallback.
	 *
	 * @param principal The X500Principal (typically from cert.getSubjectX500Principal() or cert.getIssuerX500Principal())
	 * @return The Common Name (CN) value, or the full DN if CN cannot be extracted
	 */
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
	
	/**
	 * Validates the certificate chain of the client certificate against a list of trusted CAs.
	 *
	 * This method builds a one-element certification path from the client certificate and attempts
	 * to validate it using the provided CA certificates as trust anchors. CRL checks are explicitly
	 * disabled in this method, as revocation is handled separately elsewhere.
	 *
	 * @param clientCert    The client certificate to validate
	 * @param trustedCAs    List of trusted CA certificates (parsed from PEM bundle)
	 * @return true if the chain is valid according to PKIX rules; false otherwise
	 */
	private boolean validateCertificateChain(X509Certificate[] chain, List<X509Certificate> trustedCAs) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			CertPath certPath = cf.generateCertPath(Arrays.asList(chain));

			Set<TrustAnchor> anchors = trustedCAs.stream()
				.map(ca -> new TrustAnchor(ca, null))
				.collect(Collectors.toSet());

			PKIXParameters params = new PKIXParameters(anchors);
			params.setRevocationEnabled(false); /** CRL handled separately */

			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			validator.validate(certPath, params);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	
	/**
	 * Extracts CRL (Certificate Revocation List) distribution point URLs from a given X.509 certificate.
	 *
	 * This method manually parses the CRL Distribution Points extension (OID 2.5.29.31) and attempts
	 * to locate any embedded HTTP/HTTPS URIs. No ASN.1 parsing libraries are used – the method relies
	 * on a fallback byte-level and string-based heuristic.
	 *
	 * Limitations:
	 * - ASN.1 decoding is simplistic and may fail on complex or multi-entry CRLDP structures.
	 * - Only URIs beginning with "http" are considered.
	 * - Uses ISO-8859-1 decoding as a practical fallback to preserve byte structure in the string.
	 *
	 * @param cert The X.509 certificate to inspect
	 * @return A list of CRL URLs (strings), or empty list if none found or on error
	 */
	public static List<String> extractCrlUrls(X509Certificate cert) {
		try {
			byte[] extVal = cert.getExtensionValue("2.5.29.31");
			if (extVal == null) return Collections.emptyList();

			try (ByteArrayInputStream bis = new ByteArrayInputStream(extVal)) {
				bis.read(); /**skip tag */
				int len = bis.read(); /** simplistic length */
				byte[] inner = bis.readNBytes(len);

				String asString = new String(inner, StandardCharsets.ISO_8859_1);
				List<String> urls = new ArrayList<>();
				for (String part : asString.split("URI:")) {
					if (part.startsWith("http")) {
						String url = part.split("[\\s\\n\\r]")[0];
						urls.add(url.trim());
					}
				}
				return urls;
			}
		} catch (Exception e) {
			return Collections.emptyList();
		}
	}
	
	/**
	 * Checks whether the given X.509 certificate has been revoked, using CRLs obtained via HTTP(S).
	 *
	 * This method performs an online CRL check by extracting CRL Distribution Point (CDP) URLs
	 * from the certificate, downloading each CRL, and verifying if the certificate appears in any
	 * of them as revoked.
	 *
	 * Fail-closed principle:
	 * - If CRL extraction fails, returns true (block)
	 * - If CRL download or parsing fails, returns true (block)
	 * - If no CRL URLs are found, returns true (block)
	 * - If a valid CRL is retrieved and the certificate is listed as revoked, returns true (block)
	 * - If all checks succeed and the certificate is not listed, returns false (allow)
	 *
	 * @param cert The client certificate to check
	 * @return true if the certificate is explicitly revoked or CRL validation fails; false otherwise
	 */
	public static boolean isCertificateRevoked(X509Certificate cert) {
		try {
			List<String> crlUrls = extractCrlUrls(cert);
			if (crlUrls.isEmpty()) return true; /** No CRL URLs found = fail-closed */

			for (String url : crlUrls) {
				try {
					X509CRL crl = downloadCRL(url);
					if (crl == null) return true; /**  fail-closed on null CRL */
					if (crl.isRevoked(cert)) return true; /**  explicitly revoked */
				} catch (Exception e) {
					
					/** fail-closed on download/parse error */
					return true;
				}
			}
			
			/** passed all checks, not revoked */
			return false;
			
		} catch (Exception e) {
			
			/** fail-closed on extension extraction/parsing error */
			return true;
		}
	}
	
	/**
	 * Downloads and parses a CRL (Certificate Revocation List) from the given HTTP or HTTPS URL.
	 *
	 * This method uses standard Java networking (HttpURLConnection) to perform a GET request to the
	 * provided CRL URL and attempts to parse the result as an X.509 CRL using the default
	 * CertificateFactory.
	 *
	 * Behavior:
	 * - Sets a connection and read timeout of 5 seconds.
	 * - Disables HTTP caching to always fetch the latest CRL.
	 * - Supports only HTTP/HTTPS URLs (LDAP or other protocols are not handled).
	 *
	 * @param crlUrl The URL of the CRL to download (must begin with http:// or https://)
	 * @return An X509CRL object parsed from the response
	 * @throws Exception If the download or parsing fails
	 */
	private static X509CRL downloadCRL(String crlUrl) throws Exception {
		URL url = new URL(crlUrl);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setConnectTimeout(5000);
		conn.setReadTimeout(5000);
		conn.setUseCaches(false);

		try (InputStream in = conn.getInputStream()) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509CRL) cf.generateCRL(in);
		}
	}

    @Override
    public void destroy() {
		/** No cleanup required */
	}
}
