package dev.lampirg.loginkey.security.filter;

import dev.lampirg.loginkey.security.token.UserWithVersionAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class SessionVerifyFilter extends OncePerRequestFilter {

    private final SecurityContextHolderStrategy contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final String version;

    public SessionVerifyFilter(@Value("${version}") String version) {
        this.version = version;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = contextHolderStrategy.getContext().getAuthentication();
        boolean isNotNecessary = authentication == null || !authentication.isAuthenticated();
        boolean isNotVersioned = !(authentication instanceof UserWithVersionAuthenticationToken);
        if (isNotNecessary || isNotVersioned) {
            filterChain.doFilter(request, response);
            return;
        }
        String clientVersion = ((UserWithVersionAuthenticationToken) authentication).getVersion();
        if (!StringUtils.hasLength(clientVersion)) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!clientVersion.equals(version)) {
            String message = "Invalid version. Expected " + version + " got " + clientVersion;
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
            response.getWriter().println(message);
        }
    }
}
