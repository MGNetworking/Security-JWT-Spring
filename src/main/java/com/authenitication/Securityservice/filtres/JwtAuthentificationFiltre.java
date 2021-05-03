package com.authenitication.Securityservice.filtres;

import com.authenitication.Securityservice.utilitaire.Constant;
import com.authenitication.Securityservice.utilitaire.Token_HMAC256;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtAuthentificationFiltre extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthentificationFiltre(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Déclencher par le frameworks Spring Sécurity au moment de l'authentification
     * d'un utilisateur
     *
     * @param request  HttpServletRequest qui fourni des information
     *                 de type Http pour servlet
     * @param response HttpServletResponse qui fourni des information
     *                 de type Http pour servlet
     * @return Authentication objet , l'authentification.
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {

        log.info("**************************************************");
        log.info("Mapping du username et du password de l'utilisateur  ");

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        request.getParameter("username"),
                        request.getParameter("password"));
        log.info("**************************************************");

        // Déclenche l'opération d'authentification
        return authenticationManager.
                authenticate(usernamePasswordAuthenticationToken);

    }

    /**
     * Déclencher quand l'authentification a réussi, permet de la création
     * de l'ID_Token qui composer du acces token et du refresh token.
     * L'acces token permet l'acces a l'application.
     * Le refresh token permet la création d'un acces token aprés le temps d'accés dépasser.
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {

        log.info("**************************************************");
        log.info("Creation de l'ID token ");

        User user = (User) authResult.getPrincipal();

        // Création du token d'accées
        String jwtAccessToken = Token_HMAC256.accesToken_Gt(user.getUsername(),
                request.getRequestURL().toString(), 5,
                user.getAuthorities(),
                Token_HMAC256.createHMAC256(Constant.SECRET));

        // Création du refresh token
        String jwtRefreshToken = Token_HMAC256.refreshToken(user.getUsername(),
                request.getRequestURL().toString(), 15,
                Token_HMAC256.createHMAC256(Constant.SECRET));

        // mapping des token dans Id token
        Map<String, String> id_Token = new HashMap<>();
        id_Token.put(Constant.ACCESS_TOKEN, jwtAccessToken);
        id_Token.put(Constant.REFRESH_TOKEN, jwtRefreshToken);

        log.info("**************************************************");

        // preparation des données dans l'entete au format Json
        response.setContentType(Constant.APPLICATION_JSON);
        // envoi de la response mapped au format Json
        new ObjectMapper().writeValue(response.getOutputStream(), id_Token);

    }
}
