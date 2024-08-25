package dev.lampirg.loginkey.security;

import dev.lampirg.loginkey.security.filter.ConcurrentSessionApiHeaderBasedFilter;
import dev.lampirg.loginkey.security.filter.UserDtoAuthenticationFilter;
import dev.lampirg.loginkey.security.session.ConcurrentSessionApiHeaderBasedAuthenticationStrategy;
import dev.lampirg.loginkey.security.session.RegisterApiHeaderSession;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;

import java.util.List;

@Configuration
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain
            (HttpSecurity httpSecurity,
             UserDtoAuthenticationFilter authenticationFilter,
             ConcurrentSessionApiHeaderBasedFilter concurrentSessionFilter,
             RegisterApiHeaderSession registerApiHeaderSession,
             ConcurrentSessionApiHeaderBasedAuthenticationStrategy concurrentStrategy,
             SecurityContextRepository contextRepository)
            throws Exception {
        return httpSecurity
                .addFilterAt(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(concurrentSessionFilter, ConcurrentSessionFilter.class)
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/protected").hasRole("HCKR")
                        .requestMatchers("/jojo").hasRole("JOJO")
                        .anyRequest().authenticated()
                )
                .securityContext(conf -> conf
                        .securityContextRepository(contextRepository)
                )
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .addSessionAuthenticationStrategy(concurrentStrategy)
                        .addSessionAuthenticationStrategy(registerApiHeaderSession)
                )
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN))
                )
                .requestCache(conf -> conf.requestCache(new NullRequestCache()))
                .csrf(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .build(); // wujQOmNdUBQ7fFI EZzZi13HDM4kvme
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new ProviderManager(providers);
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    @SuppressWarnings("java:S6437") // Obviously you should not keep credentials hardcoded, but I don't care
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(User.withUsername("hohol")
                .password(passwordEncoder().encode("joja"))
                .roles("JOJO")
                .build());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
