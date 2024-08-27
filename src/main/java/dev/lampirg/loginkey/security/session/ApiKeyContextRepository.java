package dev.lampirg.loginkey.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class ApiKeyContextRepository implements SecurityContextRepository {

    public static final String AUTH_HEADER = "Auth";

    private final SessionRegistry sessionRegistry;
    private final RandomSessionIdGenerator sessionIdGenerator;
    private final Map<String, SecurityContext> contextByName = new ConcurrentHashMap<>();


    @Override
    @SuppressWarnings("deprecation") // This is mandatory method to implement
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return Optional.of(requestResponseHolder)
                .map(HttpRequestResponseHolder::getRequest)
                .map(request -> request.getHeader(AUTH_HEADER))
                .map(contextByName::get)
                .orElseGet(SecurityContextHolder::createEmptyContext);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String key = sessionRegistry.getAllSessions(context.getAuthentication().getPrincipal(), false)
                .stream().max(Comparator.comparing(SessionInformation::getLastRequest))
                .map(SessionInformation::getSessionId)
                .orElseGet(this::generate);
        contextByName.put(key, context);
    }

    private String generate() {
        String key;
        do {
            key = sessionIdGenerator.generateKey();
        } while (contextByName.containsKey(key));
        return key;
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(AUTH_HEADER))
                .map(contextByName::containsKey)
                .orElse(false);
    }
}
