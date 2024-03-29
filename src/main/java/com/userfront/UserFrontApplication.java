package com.userfront;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.userfront.dao.RoleDao;
import com.userfront.dao.UserDao;
import com.userfront.domain.User;

@SpringBootApplication
public class UserFrontApplication {
	private static final Logger log = LoggerFactory.getLogger(UserFrontApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(UserFrontApplication.class, args);
	
	}
}
