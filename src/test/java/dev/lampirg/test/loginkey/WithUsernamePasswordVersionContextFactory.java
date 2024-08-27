package dev.lampirg.test.loginkey;

import dev.lampirg.loginkey.security.token.UserWithVersionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class WithUsernamePasswordVersionContextFactory implements WithSecurityContextFactory<WithMockVersionedUser> {
    @Override
    public SecurityContext createSecurityContext(WithMockVersionedUser annotation) {
        List<GrantedAuthority> authorities = Stream.concat(
                Arrays.stream(annotation.roles()).map(role -> "ROLE_" + role),
                Arrays.stream(annotation.authorities())
        )
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
        UserWithVersionAuthenticationToken token = new UserWithVersionAuthenticationToken(
                annotation.username(), annotation.password(), authorities, annotation.version()
        );
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        securityContext.setAuthentication(token);
        return securityContext;
    }
}
