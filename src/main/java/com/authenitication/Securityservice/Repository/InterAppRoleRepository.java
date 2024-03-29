package com.authenitication.Securityservice.Repository;

import com.authenitication.Securityservice.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InterAppRoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByRoleName(String roleName);
}
