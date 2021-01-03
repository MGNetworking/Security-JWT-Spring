package com.authenitication.Securityservice.service;

import com.authenitication.Securityservice.DAO.InterAppRoleRepository;
import com.authenitication.Securityservice.DAO.InterAppUserRepository;
import com.authenitication.Securityservice.entities.AppRole;
import com.authenitication.Securityservice.entities.AppUser;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class CompteService implements InterCompteService {

    private InterAppRoleRepository interAppRoleRepository;
    private InterAppUserRepository interAppUserRepository;
    private PasswordEncoder passwordEncoder;

    public CompteService(InterAppRoleRepository interAppRoleRepository,
                         InterAppUserRepository interAppUserRepository,
                         PasswordEncoder passwordEncoder) {
        this.interAppRoleRepository = interAppRoleRepository;
        this.interAppUserRepository = interAppUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser createUser(AppUser appUser) {
        String mdp = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(mdp));
        return interAppUserRepository.save(appUser);
    }

    @Override
    public AppRole createRole(AppRole appRole) {
        return interAppRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser( String appUser, String appRole) {
        AppRole role = interAppRoleRepository.findByRoleName(appRole);
        AppUser user = interAppUserRepository.findByFirstname(appUser);

        user.getAppRoles().add(role);   // Ajout un role au User en base de données

    }

    @Override
    public AppUser loadUserByName(String appUser) {
        return interAppUserRepository.findByFirstname(appUser);
    }

    @Override
    public List<AppUser> listAllUser() {
        return interAppUserRepository.findAll();
    }

}
