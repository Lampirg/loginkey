package dev.lampirg.loginkey.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;

@Component
@RequiredArgsConstructor
public class ConcurrentSessionApiHeaderBasedAuthenticationStrategy implements SessionAuthenticationStrategy {

    private final SessionRegistry sessionRegistry;
    private final int maximumSessions = 1;
    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        int allowedSessions = maximumSessions;
        if (allowedSessions == -1) {
            return;
        }
        List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
        int sessionCount = sessions.size();
        if (sessionCount < allowedSessions) {
            return;
        }
        if (sessionCount == allowedSessions) {
            String sessionId = response.getHeader(ApiKeyContextRepository.AUTH_HEADER);
            if (sessionId != null) {
                for (SessionInformation si : sessions) {
                    if (si.getSessionId().equals(sessionId)) {
                        return;
                    }
                }
            }
        }
        sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
        int maximumSessionsExceededBy = sessions.size() - allowedSessions + 1;
        List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
        for (SessionInformation session : sessionsToBeExpired) {
            session.expireNow();
        }
    }
}
