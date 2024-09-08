package baykov.daniel.cookie_auth.security.util;

import baykov.daniel.cookie_auth.model.base.StatusMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.UNAUTHORIZED;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.UNAUTHORIZED_ERR;

@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        StatusMessage error = StatusMessage.error()
                .httpStatusCode(HttpStatus.UNAUTHORIZED.value())
                .messageCode(UNAUTHORIZED_ERR)
                .message(UNAUTHORIZED)
                .build();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        new ObjectMapper().writeValue(response.getWriter(), error);
    }
}
