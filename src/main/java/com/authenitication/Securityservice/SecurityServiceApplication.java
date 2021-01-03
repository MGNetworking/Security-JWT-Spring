package com.authenitication.Securityservice;

import com.authenitication.Securityservice.entities.FormUserRole;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityServiceApplication {

    public static void main(String[] args) {

        SpringApplication.run(SecurityServiceApplication.class, args);
    }

    /**
     * Permet de cryter le mot de passe
     *
     * @return BCryptPasswordEncoder Object
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
