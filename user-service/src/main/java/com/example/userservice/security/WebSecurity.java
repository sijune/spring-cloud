package com.example.userservice.security;

import com.example.userservice.service.UserService;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private UserService userService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private Environment env;

    public WebSecurity(Environment env, UserService userService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.env = env;
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    //권한에 대한 설정
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        //http.authorizeRequests().antMatchers("/users/**").permitAll();
        http.authorizeRequests()
                .antMatchers("/error/**").permitAll()
                .antMatchers("/actuator/**").permitAll()
                .antMatchers("/**")
//                .hasIpAddress("192.168.168.251")
                .hasIpAddress("172.18.0.5")//docker network
                .and()
                .addFilter(getAuthenticationFilter()); //모든 요청에 대해 필터작업 하겠다
        http.headers().frameOptions().disable();
    }

    //필터 등록
    private AuthenticationFilter getAuthenticationFilter() throws Exception{
        AuthenticationFilter authenticationFilter
                = new AuthenticationFilter(authenticationManager(), userService, env);
//        authenticationFilter.setAuthenticationManager(authenticationManager());

        return authenticationFilter;
    }

    //인증에 대한 지원
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 패스워드 암호화에 사용될 passwordEncoder 구현체를 지정
        // 실제 로그인하도록 도와준다.
        auth.userDetailsService(userService) //유저를 찾아온다.
                .passwordEncoder(bCryptPasswordEncoder);
    }
}
