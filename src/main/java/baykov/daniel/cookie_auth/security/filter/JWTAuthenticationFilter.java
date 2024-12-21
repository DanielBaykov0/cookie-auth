package baykov.daniel.cookie_auth.security.filter;

import baykov.daniel.cookie_auth.security.util.AuthenticationTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import static baykov.daniel.cookie_auth.constant.CookieConstants.ACCESS;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI().replace(request.getContextPath(), "");

        if (requestUri.startsWith("/api/v1/auth/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<Cookie> optionalCookie = jwtTokenProvider.extractCookie(request, ACCESS.getValue());

        if (optionalCookie.isPresent()) {
            Cookie cookie = optionalCookie.get();
            Optional<String> optionalToken = jwtTokenProvider.extractToken(request, cookie.getName());
            if (optionalToken.isPresent()) {
                String token = optionalToken.get();
                if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
                    String email = jwtTokenProvider.getEmail(token);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
