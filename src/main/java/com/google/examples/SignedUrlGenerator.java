// Copyright 2019-2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.examples;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import io.javalin.http.Context;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public class SignedUrlGenerator {
  private static final Logger logger = Logger.getLogger("SignedUrlGeneratorService");
  private static final long MAX_EXPIRY = 604800L;
  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");

  private static final String V4_SIGNED_URL_SPEC =
      "https://storage.googleapis.com{resource}?{canonical_query_string}&X-Goog-Signature={hex-signature}";
  private static final String RSA_SIGNING_ALGORITHM = "GOOG4-RSA-SHA256";

  private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  public SignedUrlGenerator() throws Exception {}

  protected long getExpiry(final String expiresInExpression, final Map<String, Object> state)
      throws Exception {
    long expiryEpochSeconds = 0L;
    long durationSeconds = 0L;
    if (expiresInExpression != null && !expiresInExpression.equals("")) {
      durationSeconds = TimeResolver.resolveExpression(expiresInExpression);
      Instant now = (Instant) state.get("now");
      expiryEpochSeconds = now.plusSeconds(durationSeconds).getEpochSecond();
    }

    if (durationSeconds > MAX_EXPIRY)
      throw new IllegalStateException("the configured expiry exceeds the permitted maximum");

    if (expiryEpochSeconds <= 0)
      throw new IllegalStateException("the configured expiry must be positive");

    state.put("duration", Long.toString(durationSeconds));
    state.put("expiration", Long.toString(expiryEpochSeconds));
    state.put(
        "expiration_ISO",
        ZonedDateTime.ofInstant(Instant.ofEpochSecond(expiryEpochSeconds), ZoneOffset.UTC)
            .format(DateTimeFormatter.ISO_INSTANT));

    return expiryEpochSeconds;
  }

  private Map<String, String> sortMapByKey(Map<String, String> map) {
    return map.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .collect(
            Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (oldValue, newValue) -> oldValue,
                LinkedHashMap::new));
  }

  private Map<String, String> getCanonicalHeaders(final Map<String, Object> config)
      throws Exception {
    Map<String, String> headers = new HashMap<String, String>();
    headers.put("host", "storage.googleapis.com");
    String additionalHeaders = (String) config.get("addl-headers");
    if (additionalHeaders != null) {
      String[] items = additionalHeaders.split("\\|");
      Arrays.stream(items)
          .forEach(
              item -> {
                if (item != null && !item.equals("")) {
                  String[] kv = item.split(":", 2);
                  if (kv.length == 2
                      && kv[0] != null
                      && !kv[0].equals("")
                      && kv[1] != null
                      && !kv[1].equals("")) {
                    headers.put(kv[0].toLowerCase(), kv[1]);
                  }
                }
              });
    }
    return sortMapByKey(headers);
  }

  private String getCredentialScope(String nowFormatted) {
    return nowFormatted.substring(0, 8) + "/us/storage/goog4_request";
  }

  private String headersToString(Map<String, String> headers) {
    // TODO: handle the case of a duplicated header name
    return headers.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .map(entry -> entry.getKey().toLowerCase().trim() + ":" + entry.getValue().trim())
        .collect(Collectors.joining("\n"));
  }

  private String encodeURIComponent(String s) {
    try {
      return URLEncoder.encode(s, "UTF-8").replaceAll("\\+", "%20");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  private String queryToString(Map<String, String> query) {
    return query.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .map(entry -> entry.getKey() + "=" + encodeURIComponent(entry.getValue()))
        .collect(Collectors.joining("&"));
  }

  private Map<String, String> getCanonicalQuery(
      final Map<String, Object> config, final Map<String, Object> state) throws Exception {

    final String serviceAccountEmail = (String) state.get("serviceAccountEmail");
    Map<String, String> query = new HashMap<String, String>();
    query.put("X-Goog-Algorithm", RSA_SIGNING_ALGORITHM);
    query.put(
        "X-Goog-Credential",
        serviceAccountEmail + "/" + getCredentialScope((String) state.get("nowFormatted")));
    query.put("X-Goog-Date", (String) state.get("nowFormatted"));
    long expiryEpochSeconds = getExpiry((String) config.get("expires-in"), state);
    query.put("X-Goog-Expires", (String) state.get("duration"));
    query.put("X-Goog-SignedHeaders", (String) state.get("signedHeaders"));

    // additional query params
    String additionalQuery = (String) config.get("addl-query");
    if (additionalQuery != null) {
      String[] items = additionalQuery.split("&");
      Arrays.stream(items)
          .forEach(
              item -> {
                if (item != null && !item.equals("")) {
                  String[] kv = item.split("=", 2);
                  if (kv.length == 2 && !kv[0].equals("") && !kv[1].equals("")) {
                    query.put(kv[0], kv[1]);
                  }
                }
              });
    }
    return sortMapByKey(query);
  }

  protected String getResource(final Map<String, Object> config, final Map<String, Object> state)
      throws Exception {
    String resourceString = (String) config.get("resource");
    if (resourceString == null) {
      try {
        String bucket = (String) config.get("bucket");
        String object = (String) config.get("object");
        resourceString = "/" + bucket + "/" + object;
      } catch (IllegalStateException e) {
        throw new IllegalStateException("specify either resource or bucket + object");
      }
    }
    state.put("resource", resourceString);
    return resourceString;
  }

  private String getHashedCanonicalRequest(
      final Map<String, Object> config, final Map<String, Object> state) throws Exception {
    // CanonicalRequest =
    //   HTTP_VERB + "\n" +
    //   PATH_TO_RESOURCE + "\n" +
    //   CANONICAL_QUERY_STRING + "\n" +
    //   CANONICAL_HEADERS + "\n" +
    //   "\n" +
    //   SIGNED_HEADERS + "\n" +
    //   PAYLOAD

    Map<String, String> canonicalHeaders = getCanonicalHeaders(config);
    String signedHeaders =
        canonicalHeaders.keySet().stream()
            .map(e -> e.toLowerCase().trim())
            .collect(Collectors.joining(";"));
    state.put("signedHeaders", signedHeaders);

    String verb = (String) config.get("verb");
    String resource = getResource(config, state);
    String canonicalQueryString = queryToString(getCanonicalQuery(config, state));
    state.put("canonical_query_string", canonicalQueryString);
    String canonicalHeadersString = headersToString(canonicalHeaders);
    String payload = (String) config.get("payload");

    String canonicalRequest =
        verb
            + "\n"
            + resource
            + "\n"
            + canonicalQueryString
            + "\n"
            + canonicalHeadersString
            + "\n"
            + "\n"
            + signedHeaders
            + "\n"
            + (payload != null ? payload : "UNSIGNED-PAYLOAD");

    state.put("canonicalRequest", canonicalRequest);

    SHA256Digest digest = new SHA256Digest();
    byte[] messageBytes = canonicalRequest.getBytes(StandardCharsets.UTF_8);
    byte[] output = new byte[digest.getDigestSize()];
    digest.update(messageBytes, 0, messageBytes.length);
    digest.doFinal(output, 0);
    return org.bouncycastle.util.encoders.Hex.toHexString(output);
  }

  private String getStringToSign(final Map<String, Object> config, final Map<String, Object> state)
      throws Exception {
    // StringToSign =
    //   SIGNING_ALGORITHM + "\n" +
    //   CURRENT_DATETIME + "\n" +
    //   CREDENTIAL_SCOPE + "\n" +
    //   HASHED_CANONICAL_REQUEST
    Instant now = (Instant) state.get("now");
    final String nowFormatted =
        ZonedDateTime.ofInstant(now, ZoneOffset.UTC).format(dateTimeFormatter);

    state.put("nowFormatted", nowFormatted);
    state.put(
        "now_ISO",
        ZonedDateTime.ofInstant(now, ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));

    String stringToSign =
        RSA_SIGNING_ALGORITHM
            + "\n"
            + nowFormatted
            + "\n"
            + getCredentialScope(nowFormatted)
            + "\n"
            + getHashedCanonicalRequest(config, state);

    return stringToSign;
  }

  protected static byte[] sign_RSA_SHA256(String signingBase, KeyPair keyPair)
      throws IOException, CryptoException {
    AsymmetricKeyParameter param1 = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
    byte[] messageBytes = signingBase.getBytes(StandardCharsets.UTF_8);
    RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
    signer.init(true, param1);
    signer.update(messageBytes, 0, messageBytes.length);
    byte[] signature = signer.generateSignature();
    return signature;
  }

  // If the value of a property contains any pairs of curlies,
  // eg, {apiproxy.name}, then "resolve" the value by de-referencing
  // the state variables whose names appear between curlies.
  protected static String resolvePropertyValue(final String spec, final Map<String, Object> state) {
    final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
    final Pattern variableReferencePattern = Pattern.compile(variableReferencePatternString);
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      Object v = state.get(matcher.group(2));
      if (v != null) {
        sb.append((String) v);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  public void generateSignature(final Context ctx) throws Exception {
    if (ctx.contentType() == null || !ctx.contentType().startsWith("application/json")) {
      ctx.status(415).header("Content-Type", "text/plain").result("unsupported media type");
      return;
    }
    try {
      java.lang.reflect.Type t = new TypeToken<Map<String, Object>>() {}.getType();
      Map<String, Object> config = gson.fromJson(ctx.body(), t);
      if (config == null) {
        ctx.status(400).header("Content-Type", "text/plain").result("payload cannot be parsed");
        return;
      }
      if (!config.containsKey("service-account-key")
          || !config.containsKey("verb")
          || !config.containsKey("expires-in")) {
        ctx.status(400)
            .header("Content-Type", "text/plain")
            .result("missing required json properties");
        return;
      }
      final Instant now = Instant.now();
      Map<String, Object> state = new HashMap<String, Object>();
      state.put("now", now);

      @SuppressWarnings("unchecked")
      Map<String, String> serviceAccountInfo =
          (Map<String, String>) config.get("service-account-key");

      String clientEmail = serviceAccountInfo.get("client_email");
      if (clientEmail == null)
        throw new IllegalStateException("the service account key data is invalid");
      state.put("serviceAccountEmail", clientEmail);

      Map<String, String> result = new HashMap<String, String>();
      String stringToSign = getStringToSign(config, state);
      result.put("string-to-sign", stringToSign);

      KeyPair keypair = KeyUtility.readKeyPair(serviceAccountInfo.get("private_key"), null);
      byte[] signatureBytes = sign_RSA_SHA256(stringToSign, keypair);
      String hexSignature = org.bouncycastle.util.encoders.Hex.toHexString(signatureBytes);

      result.put("hex-signature", hexSignature);
      state.put("hex-signature", hexSignature);
      String signedUrl = resolvePropertyValue(V4_SIGNED_URL_SPEC, state);
      result.put("signed-url", signedUrl);
      result.put("now", (String) state.get("now_ISO"));
      result.put("expiration", (String) state.get("expiration_ISO"));

      String json = gson.toJson(result);
      ctx.status(200).header("Content-Type", "application/json").result(json + "\n");
    } catch (Exception exc1) {
      exc1.printStackTrace();
      Map<String, String> result = new HashMap<String, String>();
      result.put("error", "true");
      result.put("exception", exc1.toString());
      ctx.status(500).header("Content-Type", "application/json").result(gson.toJson(result) + "\n");
    }
    return;
  }
}
