package dev.lampirg.loginkey.security.provider;

import dev.lampirg.loginkey.security.token.UserWithVersionAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public ApiKeyAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
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
