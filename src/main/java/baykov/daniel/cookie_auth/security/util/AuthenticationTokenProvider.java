package baykov.daniel.cookie_auth.security.util;

import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.security.config.AuthenticationConfiguration;
import baykov.daniel.cookie_auth.service.util.ServiceUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import static baykov.daniel.cookie_auth.constant.CookieConstants.ACCESS;
import static baykov.daniel.cookie_auth.constant.CookieConstants.AUTHORITIES;
import static baykov.daniel.cookie_auth.constant.CookieConstants.HTTPS_LOCALHOST_REFERER;
import static baykov.daniel.cookie_auth.constant.CookieConstants.JWT_TYPE;
import static baykov.daniel.cookie_auth.constant.CookieConstants.LOCALHOST_ACCESS;
import static baykov.daniel.cookie_auth.constant.CookieConstants.LOCALHOST_TOTP;
import static baykov.daniel.cookie_auth.constant.CookieConstants.SAME_SITE;
import static baykov.daniel.cookie_auth.constant.CookieConstants.TOTP;
import static baykov.daniel.cookie_auth.constant.CookieConstants.TYPE;
import static baykov.daniel.cookie_auth.constant.CookieConstants.getAllCookiesValues;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EXPIRED_JWT_TOKEN;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.INVALID_JWT_TOKEN;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.JWT_CLAIM_EMPTY;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.JWT_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.UNSUPPORTED_JWT_TOKEN;
import static org.apache.tomcat.util.http.SameSiteCookies.NONE;
import static org.apache.tomcat.util.http.SameSiteCookies.STRICT;

@Component
@RequiredArgsConstructor
public class AuthenticationTokenProvider extends AuthenticationConfiguration {

    private final Supplier<SecretKey> secretKey = () -> Keys.hmacShaKeyFor(Decoders.BASE64.decode(getJwtSecret()));

    private final ServiceUtil serviceUtil;

    public final Optional<String> extractToken(HttpServletRequest request, String cookieName) {
        return Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(cookie -> Objects.equals(cookieName, cookie.getName()))
                        .map(Cookie::getValue)
                        .findAny());
    }

    public final Optional<Cookie> extractCookie(HttpServletRequest request, String cookieName) {
        return Optional.ofNullable(request.getCookies())
                .flatMap(cookies -> Arrays.stream(cookies)
                        .filter(cookie -> Objects.equals(cookieName, cookie.getName()))
                        .findAny()
                );
    }

    public final List<Cookie> extractCookies(HttpServletRequest request, Set<String> cookiesNames) {
        return Optional.ofNullable(request.getCookies())
                .map(cookies -> Arrays.stream(cookies)
                        .filter(cookie -> cookiesNames.contains(cookie.getName()))
                        .toList())
                .orElse(List.of());
    }

    public final void addCookie(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = generateAccessToken(authentication);
        String cookieName = getCookieTypeByRequestURIAndReferer(request);
        if (LOCALHOST_TOTP.getValue().equals(cookieName)) {
            Cookie cookie = new Cookie(cookieName, token);
            cookie.setHttpOnly(isCookieHttpOnly());
            cookie.setSecure(isCookieSecure());
            cookie.setMaxAge(getTotpCookieMaxAge());
            cookie.setPath(getCookiePath());
            cookie.setAttribute(SAME_SITE.getValue(), NONE.getValue());
            response.addCookie(cookie);
        } else if (LOCALHOST_ACCESS.getValue().equals(cookieName)) {
            Cookie cookie = new Cookie(cookieName, token);
            cookie.setHttpOnly(isCookieHttpOnly());
            cookie.setSecure(isCookieSecure());
            cookie.setMaxAge(getAccessCookieMaxAge());
            cookie.setPath(getCookiePath());
            cookie.setAttribute(SAME_SITE.getValue(), NONE.getValue());
            response.addCookie(cookie);
        } else if (TOTP.getValue().equals(cookieName)) {
            Cookie cookie = new Cookie(cookieName, token);
            cookie.setHttpOnly(isCookieHttpOnly());
            cookie.setSecure(isCookieSecure());
            cookie.setMaxAge(getTotpCookieMaxAge());
            cookie.setPath(getCookiePath());
            cookie.setAttribute(SAME_SITE.getValue(), STRICT.getValue());
            response.addCookie(cookie);
        } else if (ACCESS.getValue().equals(cookieName)) {
            Cookie cookie = new Cookie(cookieName, token);
            cookie.setHttpOnly(isCookieHttpOnly());
            cookie.setSecure(isCookieSecure());
            cookie.setMaxAge(getAccessCookieMaxAge());
            cookie.setPath(getCookiePath());
            cookie.setAttribute(SAME_SITE.getValue(), STRICT.getValue());
            response.addCookie(cookie);
        }
    }

    public final void removeCookies(HttpServletRequest request, HttpServletResponse response) {
        List<Cookie> cookies = extractCookies(request, getAllCookiesValues());
        if (!cookies.isEmpty()) {
            for (Cookie cookie : cookies) {
                if (HTTPS_LOCALHOST_REFERER.getValue().equals(serviceUtil.getRefererHeader(request))) {
                    if (LOCALHOST_TOTP.getValue().equals(cookie.getName()) || LOCALHOST_ACCESS.getValue().equals(cookie.getName())) {
                        cookie.setHttpOnly(isCookieHttpOnly());
                        cookie.setSecure(isCookieSecure());
                        cookie.setValue(null);
                        cookie.setMaxAge(0);
                        cookie.setPath(getCookiePath());
                        cookie.setAttribute(SAME_SITE.getValue(), NONE.name());
                        response.addCookie(cookie);
                    } else if (TOTP.getValue().equals(cookie.getName()) || ACCESS.getValue().equals(cookie.getName())) {
                        cookie.setHttpOnly(isCookieHttpOnly());
                        cookie.setSecure(isCookieSecure());
                        cookie.setValue(null);
                        cookie.setMaxAge(0);
                        cookie.setPath(getCookiePath());
                        cookie.setAttribute(SAME_SITE.getValue(), STRICT.name());
                        response.addCookie(cookie);
                    }
                }
            }
        }
    }

    private String getCookieTypeByRequestURIAndReferer(HttpServletRequest request) {
        String requestUri = request.getRequestURI().replace(request.getContextPath(), "");
        String referer = serviceUtil.getRefererHeader(request);
        if (HTTPS_LOCALHOST_REFERER.getValue().equals(referer) && requestUri.startsWith("/api/v1/auth/login")) {
            return LOCALHOST_TOTP.getValue();
        } else if (HTTPS_LOCALHOST_REFERER.getValue().equals(referer) && requestUri.startsWith("/api/v1/auth/verify-code")) {
            return LOCALHOST_ACCESS.getValue();
        } else if (requestUri.startsWith("/api/v1/auth/login")) {
            return TOTP.getValue();
        } else if (requestUri.startsWith("/api/v1/auth/verify-code")) {
            return ACCESS.getValue();
        }

        return "";
    }

    private String generateAccessToken(Authentication authentication) {
        String email = authentication.getName();
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + getJwtExpirationDate());
        return Jwts.builder()
                .header().add(Map.of(TYPE.getValue(), JWT_TYPE.getValue())).and()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim(AUTHORITIES.getValue(), authentication.getAuthorities())
                .issuedAt(new Date())
                .expiration(expireDate)
                .signWith(secretKey.get(), Jwts.SIG.HS256)
                .compact();
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey.get())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getEmail(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey.get())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    private boolean isTokenExpired(String token) {
        return Jwts.parser()
                .verifyWith(secretKey.get())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey.get())
                    .build()
                    .parse(token);

            return (!isTokenExpired(token));
        } catch (MalformedJwtException e) {
            throw StatusMessageException.error(JWT_ERR, INVALID_JWT_TOKEN);
        } catch (ExpiredJwtException e) {
            throw StatusMessageException.error(JWT_ERR, EXPIRED_JWT_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw StatusMessageException.error(JWT_ERR, UNSUPPORTED_JWT_TOKEN);
        } catch (IllegalArgumentException e) {
            throw StatusMessageException.error(JWT_ERR, JWT_CLAIM_EMPTY);
        }
    }
}
