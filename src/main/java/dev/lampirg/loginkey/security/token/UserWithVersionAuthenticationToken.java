package dev.lampirg.loginkey.security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Objects;

public class UserWithVersionAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private String version;

    public UserWithVersionAuthenticationToken(Object principal, Object credentials, String version) {
        super(principal, credentials);
        this.version = version;
    }

    public UserWithVersionAuthenticationToken(Object principal, Object credentials,
                                              Collection<? extends GrantedAuthority> authorities, String version) {
        super(principal, credentials, authorities);
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        UserWithVersionAuthenticationToken that = (UserWithVersionAuthenticationToken) o;
        return Objects.equals(version, that.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), version);
    }
}
