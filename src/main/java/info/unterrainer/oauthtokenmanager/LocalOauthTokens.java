package info.unterrainer.oauthtokenmanager;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Data
@NoArgsConstructor
@SuperBuilder(toBuilder = true)
@EqualsAndHashCode()
public class LocalOauthTokens {

	private String accessToken;
	private String refreshToken;
}
