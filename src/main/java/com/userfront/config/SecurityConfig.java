package com.userfront.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.security.SecureRandom;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

 
import com.userfront.service.UserServiceImpl.*;
 
 
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private Environment env;
	
    @Autowired
    private UserSecurityService userSecurityService;
    
    private static final String SALT = "salt"; // Salt should be protected carefully
   
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12, new SecureRandom(SALT.getBytes()));
    }
    
    
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests().antMatchers("/h2_console/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/console/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/error/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/contact/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/about/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/images/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/js/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/webjars/**").permitAll()
        .and()
        .authorizeRequests().antMatchers("/css/**").permitAll() // Enable css when logged out
        .and()
        .authorizeRequests().antMatchers("/signup/**").permitAll()
        	.and()
                .authorizeRequests().antMatchers("/").permitAll()
                .and()
                .authorizeRequests().antMatchers("/h2_console/**").permitAll();
        http.csrf().disable();
        http.headers().frameOptions().disable();
//        .authorizeRequests().antMatchers("/signup", "/saveuser").permitAll()
//        .and()
//        .authorizeRequests().antMatchers("/delete**").hasAnyAuthority("ADMIN")
//        .anyRequest().authenticated()
//        .and()
//      .formLogin()
//          .loginPage("/login")
//          .defaultSuccessUrl("/booklist")
//          .permitAll()
//          .and()
//      .logout()
//          .permitAll();
    }
   
 
   
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	 auth.inMemoryAuthentication().withUser("user").password("password").roles("USER");
        auth.userDetailsService(userSecurityService).passwordEncoder(new BCryptPasswordEncoder());
    }
   
 
}