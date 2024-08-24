package dev.lampirg.loginkey.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.random.RandomGenerator;

@RequiredArgsConstructor
public class ApiKeyContextRepository implements SecurityContextRepository {

    private static final String AUTH_HEADER = "Auth";

    private final Map<String, SecurityContext> contextByName = new ConcurrentHashMap<>();

    private final RandomGenerator randomGenerator = RandomGenerator.getDefault();


    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return Optional.of(requestResponseHolder)
                .map(HttpRequestResponseHolder::getRequest)
                .map(request -> request.getHeader(AUTH_HEADER))
                .map(contextByName::get)
                .orElseGet(SecurityContextHolder::createEmptyContext);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String key = randomGenerator.ints('0', 'z' + 1)
                .filter(value -> Character.isAlphabetic(value) || Character.isDigit(value))
                .limit(15)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        contextByName.put(key, context);
        response.setHeader("Auth", key);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader("Auth"))
                .map(contextByName::containsKey)
                .orElse(false);
    }
}
