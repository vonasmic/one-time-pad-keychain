package fel.cvut.qkd;

import com.fasterxml.jackson.databind.ObjectMapper;
import fel.cvut.bouncyCastle.BouncyCastleTLS;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * ETSI GS QKD 014 API client with mTLS and TLS 1.3 preference.
 */
public class Qkd014Client {

    private final URI baseUri;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    public Qkd014Client(String baseUrl, SSLContext sslContext, BouncyCastleTLS.TlsPolicy tlsPolicy) {
        BouncyCastleTLS.TlsPolicy effectivePolicy = tlsPolicy == null
                ? BouncyCastleTLS.TlsPolicy.defaultPolicy()
                : tlsPolicy;

        this.baseUri = URI.create(normalizeBaseUrl(baseUrl));
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClient.newBuilder()
                .sslContext(Objects.requireNonNull(sslContext, "sslContext must not be null"))
                .sslParameters(BouncyCastleTLS.createTlsParameters(effectivePolicy))
                .connectTimeout(effectivePolicy.connectTimeout())
                .build();
    }

    public static Qkd014Client fromPkcs12(
            String baseUrl,
            Path clientKeyStorePath,
            char[] clientKeyStorePassword,
            Path trustStorePath,
            char[] trustStorePassword,
            BouncyCastleTLS.TlsPolicy tlsPolicy
    ) throws Exception {
        SSLContext sslContext = BouncyCastleTLS.createBouncyCastleContextFromPkcs12(
                clientKeyStorePath,
                clientKeyStorePassword,
                trustStorePath,
                trustStorePassword
        );
        return new Qkd014Client(baseUrl, sslContext, tlsPolicy);
    }

    public KeyContainer getKey(String slaveSaeId, Integer number, Integer size) throws Qkd014ClientException {
        validateSaeId(slaveSaeId, "slaveSaeId");

        LinkedHashMap<String, String> queryParams = new LinkedHashMap<>();
        if (number != null) {
            queryParams.put("number", String.valueOf(number));
        }
        if (size != null) {
            queryParams.put("size", String.valueOf(size));
        }
        return sendGet(
                "/api/v1/keys/" + encodePathSegment(slaveSaeId) + "/enc_keys",
                queryParams,
                KeyContainer.class
        );
    }

    public KeyContainer getKey(String slaveSaeId, KeyRequest keyRequest) throws Qkd014ClientException {
        validateSaeId(slaveSaeId, "slaveSaeId");
        if (keyRequest == null || keyRequest.isSimpleGetEligible()) {
            Integer number = keyRequest == null ? null : keyRequest.number;
            Integer size = keyRequest == null ? null : keyRequest.size;
            return getKey(slaveSaeId, number, size);
        }

        return sendPost(
                "/api/v1/keys/" + encodePathSegment(slaveSaeId) + "/enc_keys",
                keyRequest,
                KeyContainer.class
        );
    }

    /**
     * ETSI 014 "Get key with key IDs" — must be called by the <em>slave</em> SAE (mTLS client cert),
     * with {@code masterSaeId} set to the master that requested the keys via {@link #getKey}.
     */
    public KeyContainer getKeyWithKeyIds(String masterSaeId, List<String> keyIds) throws Qkd014ClientException {
        validateSaeId(masterSaeId, "masterSaeId");
        validateKeyIds(keyIds);

        if (keyIds.size() == 1) {
            LinkedHashMap<String, String> queryParams = new LinkedHashMap<>();
            queryParams.put("key_ID", keyIds.get(0));
            return sendGet(
                    "/api/v1/keys/" + encodePathSegment(masterSaeId) + "/dec_keys",
                    queryParams,
                    KeyContainer.class
            );
        }

        return sendPost(
                "/api/v1/keys/" + encodePathSegment(masterSaeId) + "/dec_keys",
                KeyIdsRequest.fromKeyIds(keyIds),
                KeyContainer.class
        );
    }

    private <T> T sendGet(String path, Map<String, String> queryParams, Class<T> responseType) throws Qkd014ClientException {
        URI uri = buildUri(path, queryParams);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .GET()
                .build();
        return executeRequest(request, responseType);
    }

    private <T> T sendPost(String path, Object requestBody, Class<T> responseType) throws Qkd014ClientException {
        URI uri = buildUri(path, null);
        String jsonBody = writeJson(requestBody);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
                .build();
        return executeRequest(request, responseType);
    }

    private <T> T executeRequest(HttpRequest request, Class<T> responseType) throws Qkd014ClientException {
        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Qkd014ClientException("HTTP call interrupted", e);
        } catch (IOException e) {
            throw new Qkd014ClientException("HTTP call failed", e);
        }

        int statusCode = response.statusCode();
        String body = response.body() == null ? "" : response.body();
        if (statusCode >= 200 && statusCode < 300) {
            try {
                return objectMapper.readValue(body, responseType);
            } catch (IOException e) {
                throw new Qkd014ClientException("Failed to parse successful response body", e);
            }
        }

        ErrorResponse errorResponse = null;
        try {
            errorResponse = objectMapper.readValue(body, ErrorResponse.class);
        } catch (IOException ignored) {
            // keep fallback message with raw body
        }

        String message = errorResponse != null && errorResponse.message != null && !errorResponse.message.isBlank()
                ? errorResponse.message
                : "QKD API call failed with HTTP " + statusCode + (body.isBlank() ? "" : ": " + body);
        throw new Qkd014ClientException(message, statusCode, errorResponse);
    }

    private String writeJson(Object value) throws Qkd014ClientException {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (IOException e) {
            throw new Qkd014ClientException("Failed to serialize request body", e);
        }
    }

    private URI buildUri(String path, Map<String, String> queryParams) {
        StringBuilder sb = new StringBuilder(baseUri.toString()).append(path);
        if (queryParams != null && !queryParams.isEmpty()) {
            sb.append("?");
            boolean first = true;
            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                if (!first) {
                    sb.append("&");
                }
                sb.append(encodeQueryParam(entry.getKey()))
                        .append("=")
                        .append(encodeQueryParam(entry.getValue()));
                first = false;
            }
        }
        return URI.create(sb.toString());
    }

    private static void validateSaeId(String saeId, String fieldName) {
        if (saeId == null || saeId.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be null or blank");
        }
    }

    private static void validateKeyIds(List<String> keyIds) {
        if (keyIds == null || keyIds.isEmpty()) {
            throw new IllegalArgumentException("keyIds must not be null or empty");
        }
        for (String keyId : keyIds) {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("keyIds must not contain null or blank values");
            }
        }
    }

    private static String normalizeBaseUrl(String baseUrl) {
        Objects.requireNonNull(baseUrl, "baseUrl must not be null");
        String trimmed = baseUrl.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("baseUrl must not be blank");
        }

        URI parsed = URI.create(trimmed);
        String scheme = parsed.getScheme();
        if (scheme == null || scheme.isBlank()) {
            throw new IllegalArgumentException(
                    "baseUrl must include URL scheme (http:// or https://), got: " + trimmed
            );
        }
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("baseUrl scheme must be http or https, got: " + scheme);
        }
        if (parsed.getHost() == null || parsed.getHost().isBlank()) {
            throw new IllegalArgumentException("baseUrl must include a hostname, got: " + trimmed);
        }

        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String encodeQueryParam(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
