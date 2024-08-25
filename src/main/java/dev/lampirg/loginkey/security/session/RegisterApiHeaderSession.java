package dev.lampirg.loginkey.security.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.random.RandomGenerator;

@Component
@RequiredArgsConstructor
public class RegisterApiHeaderSession implements SessionAuthenticationStrategy {

    private final SessionRegistry sessionRegistry;

    private final RandomGenerator randomGenerator = RandomGenerator.getDefault();

    private final Set<String> alreadyGenerated = ConcurrentHashMap.newKeySet();

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
        String key = generateKey();
        sessionRegistry.registerNewSession(key, authentication.getPrincipal());
        response.setHeader(ApiKeyContextRepository.AUTH_HEADER, key);
    }

    private String generateKey() {
        String key;
        do {
            key = randomGenerator.ints('0', 'z' + 1)
                    .filter(value -> Character.isAlphabetic(value) || Character.isDigit(value))
                    .limit(15)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();
        } while (alreadyGenerated.contains(key));
        return key;
    }
}
