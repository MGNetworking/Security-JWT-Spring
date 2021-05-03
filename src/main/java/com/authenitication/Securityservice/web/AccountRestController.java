package com.authenitication.Securityservice.web;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authenitication.Securityservice.entities.AppRole;
import com.authenitication.Securityservice.entities.AppUser;
import com.authenitication.Securityservice.entities.FormUserRole;
import com.authenitication.Securityservice.utilitaire.Constant;
import com.authenitication.Securityservice.service.InterCompteService;
import com.authenitication.Securityservice.utilitaire.Token_HMAC256;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
public class AccountRestController {

    private InterCompteService interCompteService;

    public AccountRestController(InterCompteService interCompteService) {
        this.interCompteService = interCompteService;
    }

    /**
     * Recherche de tout les user que seul le rôle ADMIN peut avoir accés.
     *
     * @return List<AppUser>
     */
    @GetMapping(path = "/allUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public List<AppUser> userList() {

        return this.interCompteService.listAllUser();
    }

    /**
     * Création d'un utilisateur.
     *
     * @param appUser
     * @return AppUser Object
     */
    @PostMapping(path = "/createUser")
    @PreAuthorize("HasAuthority('ADMIN','USER')")
    public AppUser saveUser(@RequestBody AppUser appUser) {

        return this.interCompteService.createUser(appUser);
    }

    /**
     * Création d'un role que seul le rôle ADMIN peux créer.
     *
     * @param appRole type AppRole
     * @return AppRole Object
     */
    @PostMapping(path = "/createRole")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole) {

        return this.interCompteService.createRole(appRole);
    }

    /**
     * Ajout d'un role à un utilisateur. Seul le rôle
     * ADMIN peux exécuter.
     *
     * @param formUserRole
     */
    @PostMapping(path = "/addUserRole")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody FormUserRole formUserRole) {
        this.interCompteService.addRoleToUser(formUserRole.getUsername(), formUserRole.getRolename());
    }

    /**
     * Permet de recréer un token d'acces a partir du token de rafraîchissement.
     *
     * @param request
     * @param response
     */
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response)
            throws IOException {

        // recupération du token de rafraîchissement
        String tokenRefrech = request.getHeader(Constant.AUTHORIZATION);

        if (tokenRefrech != null && tokenRefrech.startsWith(Constant.BEARER)) {

            try {
                // vérification de la signature du token
                DecodedJWT decodedJWT = Token_HMAC256.MatchingToken(tokenRefrech,
                        Algorithm.HMAC256(Constant.SECRET));

                // recuperation de username contenu dans le payload (parti du token)
                String username = decodedJWT.getSubject();

                // TODO Service de verification du mote de passe valide
                // TODO si mdp plus valide , FORBIDDEN acces 403
                // TODO demander la saisi du mot de passe
                // a refaire vers service

                // recherche de l'identiter du user
                AppUser appUser = interCompteService.loadUserByName(username);

                // Création du token d'accées
                String jwtAccessToken = Token_HMAC256.accesToken_Ap(appUser.getFirstname(),
                        request.getRequestURL().toString(), 5,
                        appUser.getListeRoles(),
                        Token_HMAC256.createHMAC256(Constant.SECRET));

                // Création du refresh token
                String jwtRefreshToken = Token_HMAC256.refreshToken(username,
                        request.getRequestURL().toString(), 15,
                        Token_HMAC256.createHMAC256(Constant.SECRET));

                Map<String, String> id_Token = new HashMap<>();
                id_Token.put(Constant.ACCESS_TOKEN, jwtAccessToken);
                id_Token.put(Constant.REFRESH_TOKEN, jwtRefreshToken);

                response.setContentType(Constant.APPLICATION_JSON);
                new ObjectMapper().writeValue(response.getOutputStream(), id_Token);


            } catch (JWTVerificationException jwtvf) {

                // Échec de la verification du jwt
                log.error("problème de verification du jwt message : " + jwtvf.getMessage());
                log.error("problème de verification du jwt cause : " + jwtvf.getCause());
                log.error("problème de verification du jwt stacktrace : " + jwtvf.getStackTrace());

                response.setHeader(Constant.ERROR_MESSAGE, jwtvf.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);


            } catch (Exception ex) {

                response.setHeader(Constant.ERROR_MESSAGE, ex.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);

            }


        } else {
            throw new RuntimeException("refresh token requis");
        }

    }

}
