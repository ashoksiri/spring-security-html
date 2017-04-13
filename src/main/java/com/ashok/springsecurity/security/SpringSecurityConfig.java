/*
 * =============================================================================
 *
 *   Copyright (c) 2011-2016, The THYMELEAF team (http://www.thymeleaf.org)
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 * =============================================================================
 */
package com.ashok.springsecurity.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@ImportResource("classpath:app-config.xml")
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;
	
    public SpringSecurityConfig() {
        super();
        
    }


    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .formLogin()
                .loginPage("/login.html")
                .failureUrl("/login-error.html")
            .and()
                .logout()
                .logoutSuccessUrl("/index.html")
            .and()
                .authorizeRequests()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/shared/**").hasAnyRole("USER","ADMIN")
            .and()
                .exceptionHandling()
                .accessDeniedPage("/403.html");

    }


    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
       
    	auth.jdbcAuthentication().dataSource(dataSource)
    	.usersByUsernameQuery(
    	"select username,password, enabled from users where username=?")
    	.authoritiesByUsernameQuery(
    	"select username, role from user_roles where username=?");
    }


}
