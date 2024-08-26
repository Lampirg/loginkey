package dev.lampirg.loginkey.security.filter;

import dev.lampirg.loginkey.security.convert.UserWithVersionConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class UserDtoAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final UserWithVersionConverter userWithVersionConverter;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws AuthenticationException, IOException, ServletException {
        Authentication authentication = userWithVersionConverter.convert(request);
        if (authentication == null) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (UsernameNotFoundException e) {
            printErrorMessage(response, "Username not found");
        } catch (AuthenticationException e) {
            printErrorMessage(response, e.getMessage());
        }
        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

    private static void printErrorMessage(HttpServletResponse response, String e) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.TEXT_PLAIN_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
        response.getWriter().print(e);
    }

}
