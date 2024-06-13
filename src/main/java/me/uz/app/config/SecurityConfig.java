package me.uz.app.config;

import lombok.RequiredArgsConstructor;
import me.uz.app.repository.UserRepository;
import me.uz.app.security.JwtProperties;
import me.uz.app.security.JwtTokenAuthenticationFilter;
import me.uz.app.security.JwtTokenProvider;
import me.uz.app.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    final UserService userService;
    final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                            JwtTokenProvider tokenProvider,
                                                            ReactiveAuthenticationManager reactiveAuthenticationManager) {
        return http
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(authExchange -> {
                    authExchange.pathMatchers("/api/auth/**").permitAll()
                            .anyExchange().authenticated();
                })
                .addFilterAt(new JwtTokenAuthenticationFilter(tokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
                .exceptionHandling(exceptionHandler -> {
                    exceptionHandler.accessDeniedHandler(jwtAccessDeniedHandler)
                            .authenticationEntryPoint(jwtAuthenticationEntryPoint);
                })
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())

                .build();
    }

    private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication,
                                                               AuthorizationContext context) {

        return authentication
                .map(a -> context.getVariables().get("user").equals(a.getName()))
                .map(AuthorizationDecision::new);

    }

    @Bean
    public ReactiveUserDetailsService userDetailsService(UserRepository users) {

        return username -> users.findByUsername(username)
                .map(u -> User
                                .withUsername(u.getUsername())
                                .password(u.getPassword())
                                .authorities(u.getRoles().toArray(new String[0]))
//                        .accountExpired(!u)
//                        .credentialsExpired(!u.isActive())
//                        .disabled(!u.isActive())
//                        .accountLocked(!u.isActive())
                                .build()
                );
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder());
        return authenticationManager;
    }


    @Bean
    public JwtProperties jwtProperties() {
        return new JwtProperties();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


