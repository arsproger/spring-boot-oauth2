package com.example.springbootoauth2starter.config;

import com.example.springbootoauth2starter.security.CustomOAuth2User;
import com.example.springbootoauth2starter.security.UserDetailsServiceImpl;
import com.example.springbootoauth2starter.services.CustomOAuth2UserService;
import com.example.springbootoauth2starter.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService oauthUserService;
    private final UserService userService;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/auth/**", "/login", "/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll()
                .and()
                .oauth2Login()
                .loginPage("/auth/login")
                .userInfoEndpoint()
                .userService(oauthUserService)
                .and()
                .successHandler((request, response, authentication) -> {
                    CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();
                    userService.processOAuthPostLogin(oauthUser.getName(), oauthUser.getEmail());

//                    UserDetails userDetails = userDetailsService().loadUserByUsername(oauthUser.getEmail());
//
//                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                    response.sendRedirect("/auth/welcome");
                });
    }

}