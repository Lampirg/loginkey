package dev.lampirg.loginkey.security;

import dev.lampirg.loginkey.security.filter.UserDtoAuthenticationFilter;
import dev.lampirg.loginkey.security.session.ApiKeyContextRepository;
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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   UserDtoAuthenticationFilter authenticationFilter) throws Exception {
        return httpSecurity
                .addFilterAt(authenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(registry -> registry
                        .requestMatchers("/protected").hasRole("HCKR")
                        .requestMatchers("/jojo").hasRole("JOJO")
                        .anyRequest().authenticated())
                .anonymous(AbstractHttpConfigurer::disable)
                .securityContext(conf -> conf
                        .securityContextRepository(new ApiKeyContextRepository()))
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN)))
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new ProviderManager(providers);
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
