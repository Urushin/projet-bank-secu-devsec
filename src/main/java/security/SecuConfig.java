package security;

import org.apache.catalina.connector.Connector;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
public class SecuConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                // --- CORS Protection ---
                                // Restreint les requêtes cross-origin (seule notre propre origine est
                                // autorisée)
                                .cors(cors -> cors.configurationSource(request -> {
                                        var corsConfig = new org.springframework.web.cors.CorsConfiguration();
                                        corsConfig.setAllowedOrigins(java.util.List.of("https://localhost:8443"));
                                        corsConfig.setAllowedMethods(java.util.List.of("GET", "POST"));
                                        corsConfig.setAllowedHeaders(java.util.List.of("*"));
                                        corsConfig.setAllowCredentials(true);
                                        return corsConfig;
                                }))
                                // --- HTTPS Enforcement ---
                                // Force TOUTES les requêtes à passer par HTTPS
                                .requiresChannel(channel -> channel
                                                .anyRequest().requiresSecure())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/login", "/css/**", "/styles/**", "/images/**",
                                                                "/error")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .formLogin(form -> form
                                                .loginPage("/login")
                                                .loginProcessingUrl("/login")
                                                .defaultSuccessUrl("/accounts", true)
                                                .failureUrl("/login?error=true")
                                                .permitAll())
                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .logoutSuccessUrl("/login?logout")
                                                .invalidateHttpSession(true)
                                                .deleteCookies("JSESSIONID")
                                                .permitAll())
                                // --- Security Headers Hardening ---
                                .headers(headers -> headers
                                                .contentTypeOptions(cto -> {
                                                }) // X-Content-Type-Options: nosniff
                                                .frameOptions(fo -> fo.deny()) // X-Frame-Options: DENY (clickjacking)
                                                .xssProtection(xss -> xss
                                                                .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                                                .contentSecurityPolicy(csp -> csp
                                                                .policyDirectives(
                                                                                "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'"))
                                                // Referrer-Policy : contrôle les informations envoyées dans l'en-tête
                                                // Referer
                                                .referrerPolicy(referrer -> referrer
                                                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                                                // Strict-Transport-Security (HSTS) : force HTTPS pendant 1 an
                                                .httpStrictTransportSecurity(hsts -> hsts
                                                                .includeSubDomains(true)
                                                                .maxAgeInSeconds(31536000)))
                                // --- Session Management ---
                                .sessionManagement(session -> session
                                                .maximumSessions(1) // One session per user
                                                .expiredUrl("/login?expired=true"));

                return http.build();
        }

        /**
         * Connecteur HTTP additionnel sur le port 8080.
         * Redirige automatiquement toutes les requêtes HTTP → HTTPS (8443).
         */
        @Bean
        public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpToHttpsRedirect() {
                return factory -> {
                        Connector httpConnector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
                        httpConnector.setScheme("http");
                        httpConnector.setPort(8080);
                        httpConnector.setSecure(false);
                        httpConnector.setRedirectPort(8443);
                        factory.addAdditionalTomcatConnectors(httpConnector);
                };
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationProvider authenticationProvider) {
                return new ProviderManager(authenticationProvider);
        }

        @Bean
        public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                        PasswordEncoder passwordEncoder) {
                DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
                provider.setUserDetailsService(userDetailsService);
                provider.setPasswordEncoder(passwordEncoder);
                return provider;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}
