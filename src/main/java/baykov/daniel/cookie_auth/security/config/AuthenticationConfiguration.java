package baykov.daniel.cookie_auth.security.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;

@Getter
public class AuthenticationConfiguration {

    @Value("${auth.cookie.http-only}")
    private boolean isCookieHttpOnly;

    @Value("${auth.cookie.secure}")
    private boolean isCookieSecure;

    @Value("${auth.cookie.path}")
    private String cookiePath;

    @Value("${auth.cookie.totp.max-age}")
    private int totpCookieMaxAge;

    @Value("${auth.cookie.access.max-age}")
    private int accessCookieMaxAge;

    @Value("${auth.jwt-secret}")
    private String jwtSecret;

    @Value("${auth.jwt-expiration-milliseconds}")
    private long jwtExpirationDate;
}
