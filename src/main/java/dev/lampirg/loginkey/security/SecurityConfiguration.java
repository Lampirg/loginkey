package dev.lampirg.loginkey.security;

import dev.lampirg.loginkey.security.filter.ConcurrentSessionApiHeaderBasedFilter;
import dev.lampirg.loginkey.security.filter.UserDtoAuthenticationFilter;
import dev.lampirg.loginkey.security.session.ConcurrentSessionApiHeaderBasedAuthenticationStrategy;
import dev.lampirg.loginkey.security.session.RegisterApiHeaderSession;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final UserDtoAuthenticationFilter authenticationFilter;
    private final ConcurrentSessionApiHeaderBasedFilter concurrentSessionFilter;

    private final RegisterApiHeaderSession registerApiHeaderSession;
    private final ConcurrentSessionApiHeaderBasedAuthenticationStrategy concurrentStrategy;
    private final SecurityContextRepository contextRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)
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

}
