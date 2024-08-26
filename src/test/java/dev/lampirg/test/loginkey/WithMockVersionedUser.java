package dev.lampirg.test.loginkey;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.*;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithUsernamePasswordVersionContextFactory.class)
public @interface WithMockVersionedUser {

    String username() default "username";
    String password() default "password";
    String version() default "1.0";
    String[] roles() default "USER";
    String[] authorities() default {};

}
