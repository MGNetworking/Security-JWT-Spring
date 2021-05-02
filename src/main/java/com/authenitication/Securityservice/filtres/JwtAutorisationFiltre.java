package com.authenitication.Securityservice.filtres;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authenitication.Securityservice.security.SecurityConstant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class JwtAutorisationFiltre extends OncePerRequestFilter {
    /**
     * Ce filtre recéptionne les requête utilisateur pour verifier les droit d'accées.
     * <p>
     * Si la requête ne contient pas de token et que la resource demander ne necessite pas
     * de droit d'accés, la requête passera sans être stoper au prochain filtre.
     *
     * <p>
     * Si la resource demander necessite des droits d'accés,
     * une verification du token sera effecté.
     *
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("********************* doFilterInternal  authentication user");

        log.info("********************* " + request.getServletPath());

        if (request.getServletPath().equals("/refreshToken")) {

            log.info(" requete pour la rafraîchissement du token ou authentification d'un utilisateur ");

            // passe au filtre suivant
            filterChain.doFilter(request, response);
        } else {

            // recupération du token dans Authorization
            String authorization = request.getHeader(SecurityConstant.AUTHORIZATION);

            if (authorization != null && authorization.startsWith(SecurityConstant.bearer)) {

                log.info(" requete pour la creation du token ");

                try {
                    // recup du token sans le préfix
                    String jwt = authorization.substring(SecurityConstant.bearer.length());

                    // creation de l'algorithme de cryptage
                    Algorithm algorithm = Algorithm.HMAC256(SecurityConstant.SECRET);

                    // creation jwt de verification
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                    // verification du token envoyer dans la requête et recupére les claims
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);

                    // recuperation de username contenu dans le payload (parti du token)
                    String username = decodedJWT.getSubject();

                    // recupere les roles
                    String[] roles = decodedJWT.getClaim(SecurityConstant.roles).asArray(String.class);

                    // convertion des roles en type GrantedAuthority
                    Collection<GrantedAuthority> authorities = new ArrayList<>();

                    for (String r : roles) {
                        authorities.add(new SimpleGrantedAuthority(r));
                    }

                    // creation d'un objet user authentification par valider le droit de passage
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // authentifie l'utilisateur
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // passe au filtre suivant
                    filterChain.doFilter(request, response);

                } catch (Exception ex) {

                    log.error("********************* error : " + ex.getMessage());
                    log.error("********************* error : " + ex.getCause());
                    log.error("********************* error : " + ex.getClass());
                    log.error("********************* error : " + ex.getLocalizedMessage());
                    log.error("********************* error : " + ex.getStackTrace());
                    log.error("********************* error : " + ex);


                    // en cas de probléme
                    response.setHeader(SecurityConstant.error, ex.getMessage());
                    // error 403
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);


                }


            } else {

                // passe au filtre suivant sans verification
                filterChain.doFilter(request, response);

            }
        }
    }
}
