package dev.lampirg.loginkey.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RegisterApiHeaderSession implements SessionAuthenticationStrategy {

    private final SessionRegistry sessionRegistry;

    private final RandomSessionIdGenerator sessionIdGenerator;

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        String key;
        do {
            key = sessionIdGenerator.generateKey();
        } while (sessionRegistry.getSessionInformation(key) != null);
        sessionRegistry.registerNewSession(key, authentication.getPrincipal());
        response.setHeader(ApiKeyContextRepository.AUTH_HEADER, key);
    }
}
