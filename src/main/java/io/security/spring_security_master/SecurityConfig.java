package io.security.spring_security_master;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
        return http.build();
    }

    /**
     * user 주입 방식 2가지(yml, UserDeatilService)
     * yml 설정 파일의 user와 중복 시 Bean의 user가 우선됨
     */
    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user = User
                .withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();

        UserDetails user2 = User
                .withUsername("user2")
                .password("{noop}2222")
                .roles("USER")
                .build();

        UserDetails user3 = User
                .withUsername("user3")
                .password("{noop}3333")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, user2, user3);
    }
}
