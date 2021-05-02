package com.authenitication.Securityservice.filtres;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.authenitication.Securityservice.security.SecurityConstant;
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
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthentificationFiltre extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthentificationFiltre(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Déclencher quand l'utilisateur va tenter de s'authentifier
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        log.info("********************* attemptAuthentication ");

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("Username : " + username);
        log.info("Password : " + password);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, password);

        // déclenche l'opération d'authentification
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
                                            Authentication authResult) throws IOException, ServletException {

        log.info("********************* successfulAuthentication");

        User user = (User) authResult.getPrincipal();

        // création d'un algorithme de crytage avec le secret
        Algorithm algorithm = Algorithm.HMAC256(SecurityConstant.SECRET);

        /**
         * Creation de l'acces token avec :
         * le username
         * le temps de validité du token ( 5 min )
         * les roles
         * la signature
         */
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim(SecurityConstant.roles, user.getAuthorities()
                        .stream()
                        .map(grantedAuthority -> grantedAuthority.getAuthority())
                        .collect(Collectors.toList()))
                .sign(algorithm);

        /**
         * Creation du refresh token avec :
         * le username
         * le temps de validité du token ( 15 min )
         * la signature
         */
        String jwtRefreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        Map<String, String> id_Token = new HashMap<>();
        id_Token.put(SecurityConstant.tokenAcces, jwtAccessToken);
        id_Token.put(SecurityConstant.tokenRefresh, jwtRefreshToken);

        // envoi de données au format Json dans l'en téte de la reponse
        response.setContentType(SecurityConstant.ctJson);
        // creation au format json de cette reponse
        new ObjectMapper().writeValue(response.getOutputStream(), id_Token);

    }
}
