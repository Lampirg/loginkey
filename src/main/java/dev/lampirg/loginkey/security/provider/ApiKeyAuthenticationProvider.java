package dev.lampirg.loginkey.security.provider;

import dev.lampirg.loginkey.security.token.UserWithVersionAuthenticationToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final String version;

    public ApiKeyAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService, @Value("${version}") String version) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.version = version;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        if (authentication.isAuthenticated()) {
            return authentication;
        }
        UserWithVersionAuthenticationToken withVersion = (UserWithVersionAuthenticationToken) authentication;
        if (!withVersion.getVersion().equals(version)) {
            throw new CredentialsExpiredException(MessageFormat.format(
                    "user version {0} is incompatible with server version {1}", withVersion.getVersion(), version
            ));
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(withVersion.getPrincipal().toString());
        if (!passwordEncoder.matches(withVersion.getCredentials().toString(), userDetails.getPassword())) {
            throw new BadCredentialsException("password is invalid");
        }
        return new UserWithVersionAuthenticationToken(withVersion.getPrincipal(), withVersion.getCredentials(),
                userDetails.getAuthorities(), withVersion.getVersion());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UserWithVersionAuthenticationToken.class);
    }
}
