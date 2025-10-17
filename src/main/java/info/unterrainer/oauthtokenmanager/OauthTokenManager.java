package info.unterrainer.oauthtokenmanager;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import info.unterrainer.commons.httpserver.exceptions.ForbiddenException;
import info.unterrainer.commons.httpserver.exceptions.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class OauthTokenManager {

	private final String host;
	private final String realm;

	private String jwksUrl;
	private final Map<String, PublicKey> publicKeysByKid = new ConcurrentHashMap<>();
	private volatile long lastFetchTimestamp = 0L;

	private static final long REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours cache-validity

	public synchronized void initPublicKeys() {
		String correctedHost = host.endsWith("/") ? host : host + "/";
		String correctedRealm = realm.startsWith("/") ? realm.substring(1) : realm;
		jwksUrl = correctedHost + "realms/" + correctedRealm + "/protocol/openid-connect/certs";

		try {
			log.info("Fetching JWKS from [{}]", jwksUrl);
			ObjectMapper om = new ObjectMapper();
			HttpClient client = HttpClient.newHttpClient();
			HttpRequest req = HttpRequest.newBuilder().uri(URI.create(jwksUrl)).GET().build();
			HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
			if (res.statusCode() >= 300)
				throw new IOException("Failed to fetch JWKS: HTTP " + res.statusCode());

			JsonNode jwks = om.readTree(res.body());
			Map<String, PublicKey> newMap = new ConcurrentHashMap<>();

			for (JsonNode key : jwks.withArray("keys")) {
				if (!key.has("kid") || !key.has("n") || !key.has("e"))
					continue;
				String kid = key.get("kid").asText();
				String n = key.get("n").asText();
				String e = key.get("e").asText();

				BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
				BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

				RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
				PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(spec);
				newMap.put(kid, pk);
			}

			publicKeysByKid.clear();
			publicKeysByKid.putAll(newMap);
			lastFetchTimestamp = System.currentTimeMillis();

			log.info("Loaded {} JWKS keys from {} (kids={})", newMap.size(), jwksUrl, newMap.keySet());
		} catch (Exception e) {
			log.error("Failed to fetch JWKS keys from [{}]", jwksUrl, e);
			throw new IllegalStateException("Could not load JWKS from " + jwksUrl, e);
		}
	}

	public String extractKidFromJwt(String jwt) {
		try {
			String[] parts = jwt.split("\\.");
			if (parts.length < 2)
				return null;
			String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
			JsonNode node = new ObjectMapper().readTree(headerJson);
			return node.has("kid") ? node.get("kid").asText() : null;
		} catch (Exception e) {
			return null;
		}
	}

	public PublicKey getKeyForKid(String kid) {
		if (publicKeysByKid.isEmpty() || System.currentTimeMillis() - lastFetchTimestamp > REFRESH_INTERVAL_MS)
			initPublicKeys();

		PublicKey pk = publicKeysByKid.get(kid);
		if (pk == null) {
			log.warn("No cached key for kid='{}'. Refreshing JWKS...", kid);
			initPublicKeys();
			pk = publicKeysByKid.get(kid);
			if (pk == null) {
				log.error("JWKS refresh did not contain kid='{}'. Possible misconfiguration or key rotation issue.",
						kid);
				throw new UnauthorizedException("Unknown key ID: " + kid);
			}
		}
		return pk;
	}

	public String checkAccess(String accessToken) {
		try {
			TokenVerifier<AccessToken> tokenVerifier = persistUserInfoInContext(accessToken);
			if (tokenVerifier == null)
				throw new UnauthorizedException("Token could not be parsed.");

			String rawJwt = accessToken.startsWith("Bearer ") ? accessToken.substring(7) : accessToken;
			String kid = extractKidFromJwt(rawJwt);
			if (kid == null)
				throw new UnauthorizedException("Token has no 'kid' header.");

			PublicKey pk = getKeyForKid(kid);

			try {
				tokenVerifier.publicKey(pk);
				tokenVerifier.verifySignature();
				tokenVerifier.verify();
			} catch (VerificationException e) {
				// Retry once after forced JWKS refresh
				log.warn("Signature verification failed for kid='{}'. Retrying after JWKS refresh.", kid);
				initPublicKeys();
				PublicKey refreshedPk = publicKeysByKid.get(kid);
				if (refreshedPk == null) {
					log.error("Token verification failed after refresh. kid='{}' unknown.", kid);
					throw new UnauthorizedException("Invalid token signature. kid=" + kid, e);
				}
				try {
					tokenVerifier.publicKey(refreshedPk);
					tokenVerifier.verifySignature();
					tokenVerifier.verify();
				} catch (VerificationException e2) {
					throw new UnauthorizedException("Token signature invalid after refresh (kid=" + kid + ")", e2);
				}
			}

			AccessToken token = tokenVerifier.getToken();
			return (String) token.getOtherClaims().get("tenants_read");

		} catch (VerificationException e) {
			throw new UnauthorizedException("Token verification failed.", e);
		} catch (UnauthorizedException | ForbiddenException e) {
			throw e;
		} catch (Exception e) {
			log.error("Error checking token.", e);
			throw new UnauthorizedException("Error verifying token: " + e.getMessage(), e);
		}
	}

	private TokenVerifier<AccessToken> persistUserInfoInContext(String authorizationHeader) {
		if (authorizationHeader == null || authorizationHeader.isBlank())
			return null;

		if (authorizationHeader.toLowerCase().startsWith("bearer "))
			authorizationHeader = authorizationHeader.substring(7);

		try {
			TokenVerifier<AccessToken> tokenVerifier = TokenVerifier.create(authorizationHeader, AccessToken.class);
			AccessToken token = tokenVerifier.getToken();
			if (token == null || !token.isActive()) {
				log.warn("Token is inactive or null.");
				return null;
			}
			return tokenVerifier;
		} catch (VerificationException e) {
			log.warn("Token was checked and deemed invalid.", e);
			return null;
		}
	}

	public LocalOauthTokens getTokensFromCredentials(String clientId, String username, String password) {
		return getTokensFromCredentials(clientId, null, username, password);
	}

	public LocalOauthTokens getTokensFromCredentials(String clientId, String clientSecret, String username,
			String password) {
		try {
			String tokenEndpoint = host.endsWith("/") ? host : host + "/";
			tokenEndpoint += "realms/" + realm + "/protocol/openid-connect/token";

			String form = "grant_type=password" + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
					+ "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8) + "&password="
					+ URLEncoder.encode(password, StandardCharsets.UTF_8);
			if (clientSecret != null)
				form += "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(tokenEndpoint))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.POST(HttpRequest.BodyPublishers.ofString(form))
					.build();

			HttpClient client = HttpClient.newHttpClient();
			HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
			if (res.statusCode() >= 300)
				throw new IOException("Token request failed: HTTP " + res.statusCode() + " - " + res.body());

			ObjectMapper mapper = new ObjectMapper();
			JsonNode json = mapper.readTree(res.body());
			log.info("Token received successfully.");
			return LocalOauthTokens.builder()
					.accessToken(json.get("access_token").asText())
					.refreshToken(json.get("refresh_token").asText())
					.build();

		} catch (Exception e) {
			log.error("Error obtaining tokens from Keycloak.", e);
			throw new IllegalStateException("Unable to get token", e);
		}
	}
}
