package dev.lampirg.loginkey.security.filter;

import dev.lampirg.loginkey.security.session.ApiKeyContextRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class ConcurrentSessionApiHeaderBasedFilter extends OncePerRequestFilter {

    private final SessionRegistry sessionRegistry;
    private final SecurityContextHolderStrategy contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    public ConcurrentSessionApiHeaderBasedFilter(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String sessionId = request.getHeader(ApiKeyContextRepository.AUTH_HEADER);
        if (sessionId == null) {
            filterChain.doFilter(request, response);
            return;
        }
        SessionInformation sessionInformation = sessionRegistry.getSessionInformation(sessionId);
        if (sessionInformation == null) {
            filterChain.doFilter(request, response);
            return;
        }
        if (sessionInformation.isExpired()) {
            contextHolderStrategy.clearContext();
        } else {
            sessionRegistry.refreshLastRequest(sessionId);
        }
        filterChain.doFilter(request, response);
    }
}
