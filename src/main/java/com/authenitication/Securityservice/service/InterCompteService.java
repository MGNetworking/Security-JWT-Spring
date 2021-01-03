package com.authenitication.Securityservice.service;

import com.authenitication.Securityservice.entities.AppRole;
import com.authenitication.Securityservice.entities.AppUser;
import java.util.List;

public interface InterCompteService {

    AppUser createUser(AppUser appUser);

    AppRole createRole(AppRole appRole);

    void addRoleToUser(String appRole, String appUser);

    AppUser loadUserByName(String appUser);

    List<AppUser> listAllUser();

}
