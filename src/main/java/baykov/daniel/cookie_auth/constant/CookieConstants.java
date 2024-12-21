package baykov.daniel.cookie_auth.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Getter
@RequiredArgsConstructor
public enum CookieConstants {

    ACCESS("__Host_access-token"),
    LOCALHOST_ACCESS("__Secure_access-token"),
    TOTP("__Host_totp-token"),
    LOCALHOST_TOTP("__Secure_totp-token"),
    HTTPS_LOCALHOST_REFERER("https://localhost"),
    SAME_SITE("SameSite"),
    TYPE("type"),
    JWT_TYPE("jwt-type"),
    AUTHORITIES("authorities");

    private final String value;

    public Set<CookieConstants> getAllCookies() {
        return Set.of(ACCESS,LOCALHOST_ACCESS, TOTP, LOCALHOST_TOTP);
    }

    public static Set<String> getAllCookiesValues() {
        return Set.of(ACCESS.getValue(),LOCALHOST_ACCESS.getValue(), TOTP.getValue(), LOCALHOST_TOTP.getValue());
    }
}
