package info.unterrainer.oauthtokenmanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

public class JwksTests {

	private static HttpServer jwksServer;
	private static String jwksUrl;
	private static KeyPair key1;
	private static KeyPair key2;

	@BeforeAll
	static void startJwksServer() throws Exception {
		// generate two RSA key pairs
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		key1 = gen.generateKeyPair();
		key2 = gen.generateKeyPair();

		// minimal JWKS JSON
		String jwksJson = buildJwksJson(List.of(new KeyEntry("key-1", (RSAPublicKey) key1.getPublic()),
				new KeyEntry("key-2", (RSAPublicKey) key2.getPublic())));

		// start simple JWKS HTTP server
		jwksServer = HttpServer.create(new InetSocketAddress(0), 0);
		jwksServer.createContext("/realms/Cms/protocol/openid-connect/certs", exchange -> {
			byte[] bytes = jwksJson.getBytes();
			exchange.sendResponseHeaders(200, bytes.length);
			exchange.getResponseBody().write(bytes);
			exchange.close();
		});
		jwksServer.start();
		int port = jwksServer.getAddress().getPort();
		jwksUrl = "http://localhost:" + port;
	}

	@AfterAll
	static void stopServer() {
		jwksServer.stop(0);
	}

	private static record KeyEntry(String kid, RSAPublicKey pub) {
	}

	private static String buildJwksJson(List<KeyEntry> keys) throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("{\"keys\":[");
		boolean first = true;
		for (KeyEntry k : keys) {
			if (!first)
				sb.append(",");
			first = false;
			String n = Base64.getUrlEncoder().withoutPadding().encodeToString(k.pub.getModulus().toByteArray());
			String e = Base64.getUrlEncoder().withoutPadding().encodeToString(k.pub.getPublicExponent().toByteArray());
			sb.append("{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"")
					.append(k.kid)
					.append("\",\"n\":\"")
					.append(n)
					.append("\",\"e\":\"")
					.append(e)
					.append("\"}");
		}
		sb.append("]}");
		return sb.toString();
	}

	@Test
	void loadsAllKeysAndCachesThem() {
		OauthTokenManager tm = new OauthTokenManager(jwksUrl, "Cms");
		tm.initPublicKeys();
		assertThat(tm).extracting("publicKeysByKid")
				.asInstanceOf(InstanceOfAssertFactories.MAP)
				.containsKeys("key-1", "key-2");
	}

	@Test
	void verifiesKeyLookupWithoutSignatureCheck() throws Exception {
		// Arrange
		OauthTokenManager tm = new OauthTokenManager(jwksUrl, "Cms") {
			@Override
			public String checkAccess(String accessToken) {
				// Only test the key-selection, not the actual signature verification
				String rawJwt = accessToken.startsWith("Bearer ") ? accessToken.substring(7) : accessToken;
				String kid = extractKidFromJwt(rawJwt);
				PublicKey key = getKeyForKid(kid);
				assertThat(key).isNotNull();
				return "dummy-tenant"; // Fake success
			}
		};
		tm.initPublicKeys();

		// Build dummy JWT with kid=key-1
		String header = Base64.getUrlEncoder()
				.withoutPadding()
				.encodeToString("{\"alg\":\"RS256\",\"kid\":\"key-1\"}".getBytes());
		String payload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes());
		String fakeSig = Base64.getUrlEncoder().withoutPadding().encodeToString("sig".getBytes());
		String jwt = header + "." + payload + "." + fakeSig;

		assertThatCode(() -> tm.checkAccess(jwt)).doesNotThrowAnyException();
	}

	@Test
	void fetchesJwksOverHttp() throws Exception {
		HttpClient client = HttpClient.newHttpClient();
		HttpResponse<String> res = client.send(
				HttpRequest.newBuilder(URI.create(jwksUrl + "/realms/Cms/protocol/openid-connect/certs")).build(),
				HttpResponse.BodyHandlers.ofString());
		assertThat(res.statusCode()).isEqualTo(200);
		assertThat(res.body()).contains("key-1").contains("key-2");
	}
}
