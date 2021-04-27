package com.authenitication.Securityservice.web;

import com.authenitication.Securityservice.entities.AppRole;
import com.authenitication.Securityservice.entities.AppUser;
import com.authenitication.Securityservice.entities.FormUserRole;
import com.authenitication.Securityservice.service.InterCompteService;
import jdk.management.resource.internal.ApproverGroup;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountRestController {

    private InterCompteService interCompteService;

    public AccountRestController(InterCompteService interCompteService) {
        this.interCompteService = interCompteService;
    }

    /**
     * Recherche de tout les user
     *
     * @return List<AppUser>
     */
    @GetMapping(path = "/allUser")
    public List<AppUser> userList() {

        return this.interCompteService.listAllUser();
    }

    /**
     * Création d'un utilisateur
     *
     * @param appUser
     * @return AppUser Object
     */
    @PostMapping(path = "/createUser")
    public AppUser saveUser(@RequestBody AppUser appUser) {

        return this.interCompteService.createUser(appUser);
    }

    /**
     * Création d'un role.
     *
     * @param appRole
     * @return AppRole Object
     */
    @PostMapping(path = "/createRole")
    public AppRole saveRole(@RequestBody AppRole appRole) {

        return this.interCompteService.createRole(appRole);
    }

    /**
     * Ajout d'un role a user
     *
     * @param formUserRole
     */
    @PostMapping(path = "/addUserRole")
    public void addRoleToUser(@RequestBody FormUserRole formUserRole) {
        this.interCompteService.addRoleToUser(formUserRole.getUsername(), formUserRole.getRolename());
    }

}
