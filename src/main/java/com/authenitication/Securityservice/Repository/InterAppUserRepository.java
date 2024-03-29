package com.authenitication.Securityservice.Repository;

import com.authenitication.Securityservice.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InterAppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByFirstname(String userName);

}
