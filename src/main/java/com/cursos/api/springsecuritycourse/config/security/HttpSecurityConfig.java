package com.cursos.api.springsecuritycourse.config.security;

import com.cursos.api.springsecuritycourse.config.security.filter.JwtAuthenticationFilter;
import com.cursos.api.springsecuritycourse.persistence.util.RolePermission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class HttpSecurityConfig {
    @Autowired
    private AuthenticationProvider authenticationProvider;
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(HttpSecurityConfig::buildRequestMatchers)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider);
        return http.build();
    }

    private static AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry buildRequestMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry auth) {
        return auth
                .requestMatchers(HttpMethod.POST, "/customers", "/auth/authenticate").permitAll()
                .requestMatchers(HttpMethod.GET, "/auth/validate-token").permitAll()

                .requestMatchers(HttpMethod.GET, "/products")
                .hasAuthority(RolePermission.READ_ALL_PRODUCTS.name())
                .requestMatchers(HttpMethod.GET, "/products/{id}")
                .hasAuthority(RolePermission.READ_ONE_PRODUCT.name())
                .requestMatchers(HttpMethod.POST, "/products")
                .hasAuthority(RolePermission.CREATE_ONE_PRODUCT.name())
                .requestMatchers(HttpMethod.PUT, "/products/{id}")
                .hasAuthority(RolePermission.UPDATE_ONE_PRODUCT.name())
                .requestMatchers(HttpMethod.PUT, "/products/{id}/disabled")
                .hasAuthority(RolePermission.DISABLE_ONE_PRODUCT.name())

                .requestMatchers(HttpMethod.GET, "/categories")
                .hasAuthority(RolePermission.READ_ALL_CATEGORIES.name())
                .requestMatchers(HttpMethod.GET, "/categories/{id}")
                .hasAuthority(RolePermission.READ_ONE_CATEGORY.name())
                .requestMatchers(HttpMethod.POST, "/categories")
                .hasAuthority(RolePermission.CREATE_ONE_CATEGORY.name())
                .requestMatchers(HttpMethod.PUT, "/categories/{id}")
                .hasAuthority(RolePermission.UPDATE_ONE_CATEGORY.name())
                .requestMatchers(HttpMethod.PUT, "/categories/{id}/disabled")
                .hasAuthority(RolePermission.DISABLE_ONE_CATEGORY.name())


                .requestMatchers(HttpMethod.PUT, "/auth/profile")
                .hasAuthority(RolePermission.READ_MY_PROFILE.name())


                .anyRequest().authenticated();
    }
}
