package com.secucom.springjwt;

import java.util.Optional;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

import com.secucom.springjwt.models.ERole;
import com.secucom.springjwt.models.Role;
import com.secucom.springjwt.repository.RoleRepository;

@SpringBootApplication
public class SpringBootSecurityJwtApplication {

	public static void main(String[] args) {
		ApplicationContext ctx = SpringApplication.run(SpringBootSecurityJwtApplication.class, args);

		RoleRepository roleRepos = ctx.getBean(RoleRepository.class);

		try {
			roleRepos.findByName(ERole.ROLE_USER).get();
		} catch (Exception e) {
			// TODO: handle exception
			Role userRole = new Role();
			// userRole.setId(1L);
			userRole.setName(ERole.ROLE_USER);
			roleRepos.save(userRole);
		}

		try {
			roleRepos.findByName(ERole.ROLE_ADMIN).get();
		} catch (Exception e) {
			// TODO: handle exception
			Role adminRole = new Role();
			// adminRole.setId(2L);
			adminRole.setName(ERole.ROLE_ADMIN);
			roleRepos.save(adminRole);

		}

	}

}
