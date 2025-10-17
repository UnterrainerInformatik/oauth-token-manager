package info.unterrainer.oauthtokenmanager;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

public class KeycloakTests {

	@Test
	public void OneTmCanDecodeTokenFromAnotherTm() {
		OauthTokenManager tm1 = new OauthTokenManager("https://keycloak.lan.elite-zettl.at", "Cms");
		OauthTokenManager tm2 = new OauthTokenManager("https://keycloak.lan.elite-zettl.at", "Cms");

		LocalOauthTokens lot = tm1.getTokensFromCredentials("CMS", "gerald.unterrainer@cms-building.at",
				"9BZOx5EBJRjN4azmkhhA");
		assertThat(lot).isNotNull();
		String tenantId = tm2.checkAccess(lot.getAccessToken());
		assertThat(tenantId).isNotNull();
	}
}
