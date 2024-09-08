package baykov.daniel.cookie_auth.security.util;

import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.security.config.JwtConfiguration;
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
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static baykov.daniel.cookie_auth.constant.Constants.AUTHORITIES;
import static baykov.daniel.cookie_auth.constant.Constants.JWT_TYPE;
import static baykov.daniel.cookie_auth.constant.Constants.TYPE;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.EXPIRED_JWT_TOKEN;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.INVALID_JWT_TOKEN;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.JWT_CLAIM_EMPTY;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.JWT_ERR;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.UNSUPPORTED_JWT_TOKEN;
import static baykov.daniel.cookie_auth.entity.TokenType.TokenTypeEnum.ACCESS;
import static org.apache.tomcat.util.http.SameSiteCookies.NONE;

@Component
public class JWTTokenProvider extends JwtConfiguration {

    private final Supplier<SecretKey> secretKey = () -> Keys.hmacShaKeyFor(Decoders.BASE64.decode(getJwtSecret()));

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

    public final void addCookie(HttpServletResponse response, Authentication authentication, TokenType.TokenTypeEnum type) {
        if (type.getValue().equals(ACCESS.getValue())) {
            String token = generateAccessToken(authentication);
            Cookie cookie = new Cookie(type.getValue(), token);
            cookie.setHttpOnly(true);
//            cookie.setSecure(true);
            cookie.setMaxAge(120);
            cookie.setPath("/");
            cookie.setAttribute("SameSite", NONE.name());
            response.addCookie(cookie);
        }
    }

    public final void removeCookie(HttpServletRequest request, HttpServletResponse response, String cookieName) {
        Optional<Cookie> optionalCookie = extractCookie(request, cookieName);
        if (optionalCookie.isPresent()) {
            Cookie cookie = optionalCookie.get();
            cookie.setHttpOnly(true);
            cookie.setValue(null);
            cookie.setMaxAge(0);
            cookie.setPath("/");
            cookie.setAttribute("SameSite", NONE.name());
            response.addCookie(cookie);
        }
    }

    private String generateAccessToken(Authentication authentication) {
        String email = authentication.getName();
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + getJwtExpirationDate());
        return Jwts.builder()
                .header().add(Map.of(TYPE, JWT_TYPE)).and()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim(AUTHORITIES, authentication.getAuthorities())
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
