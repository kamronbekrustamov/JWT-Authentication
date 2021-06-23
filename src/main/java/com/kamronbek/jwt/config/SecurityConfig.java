package com.kamronbek.jwt.config;


import com.kamronbek.jwt.filter.JwtTokenGeneratorFilter;
import com.kamronbek.jwt.filter.JwtTokenValidatorFilter;
import com.kamronbek.jwt.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Disabling HTTP BASIC Authentication
        http.httpBasic().disable();

        // Disabling Session Management
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Adding JWT Filters
        http.addFilterBefore(new JwtTokenValidatorFilter(userService), BasicAuthenticationFilter.class)
                .addFilterAfter(new JwtTokenGeneratorFilter(), BasicAuthenticationFilter.class);

        // Disabling CSRF
        http.csrf().disable();

        // Configuring CORS
        http.cors().configurationSource(httpServletRequest -> {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(List.of("http:localhost:3000"));
            configuration.setAllowedMethods(List.of("*"));
            configuration.setAllowCredentials(true);
            configuration.setAllowedHeaders(List.of("*"));
            configuration.setExposedHeaders(List.of("Authorization"));
            configuration.setMaxAge(3600L);
            return configuration;
        });

        // Config for http://localhost:8080/api/v1/users
        http.authorizeRequests()
                .antMatchers("/api/v1/users/authenticate").authenticated()
                .antMatchers("/api/v1/users/register").anonymous();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userService);
        return provider;
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
