package com.example.gatewayzuul;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
                // authorization requests config
                .authorizeRequests()
                // allow all who are accessing "auth" service
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                //Tillåter alla som ska till accessDenied sidan
                .antMatchers( "/accessDenied.html").permitAll()
                // Any other request must be authenticated
                .anyRequest().authenticated()
                .and()
                //https://en.wikipedia.org/wiki/Cross-site_request_forgery

                // handle an authorized attempts
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendRedirect("/accessDenied.html"))
                .and()
                // Add a filter to validate the tokens with every request
                ;
    }

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }
}
