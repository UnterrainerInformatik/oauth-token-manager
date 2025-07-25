package info.unterrainer.oauthtokenmanager;

import org.keycloak.representations.AccessToken;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
@NoArgsConstructor
@SuperBuilder(toBuilder = true)
@EqualsAndHashCode()
public class RemoteOauthToken {

	private AccessToken accessToken;

	public Long getRemoteTenantId() {
		if (accessToken == null)
			return null;
		String tenantId = (String) accessToken.getOtherClaims().get("value_tenant");
		if (tenantId == null || tenantId.isBlank())
			return null;
		try {
			return Long.parseLong(tenantId);
		} catch (NumberFormatException e) {
			log.warn("Invalid tenant ID in token: {}", tenantId, e);
			return null;
		}
	}
}
