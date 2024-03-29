package com.authenitication.Securityservice.filtres;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authenitication.Securityservice.utilitaire.Constant;
import com.authenitication.Securityservice.utilitaire.Token_HMAC256;
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
     * Ce filtre récéptionne les requêtes des utilisateur pour la vérification de leurs droits d'accées.
     * Puis après traitement passe au prochain fitre :
     * {@link com.authenitication.Securityservice.filtres.JwtAuthentificationFiltre}
     *
     * @param request     HttpServletRequest qui fourni des information
     *                    de type Http pour servlet
     * @param response    HttpServletResponse qui fourni des information
     *                    de type Http pour servlet
     * @param filterChain FilterChain qui permet de passe au prochain filtre
     * @throws ServletException renvoi les exception générale de servlet
     * @throws IOException      renvoi une requête au format html pour
     *                          les erreur de type 403.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("**************************************************");
        log.info("Filtre d'autorisation ");

        /**
         * Access-Control-Allow-Origin => Accès contrôle Autorisation Origine
         * autorisation des demande d'acces de toutes les origines
         */
        response.addHeader("Access-Control-Allow-Origin", "*");

        /**
         *   Access Controle Allow Header => Accès contrôle Autorisation en-tete
         *   Autorise les demandes qui possedant les en-tete suivant.
         */
        response.addHeader("Access-Control-Allow-Headers",
                "Origin, Accept, X-Requested-With, Content-Type, " +
                        "Access-Control-Request-Method, " +
                        "Access-Control-Request-Headers," +
                        "Authorization");

        /**
         * Access-Control-Expose-Headers => Accès contrôle Exposition Autorisation
         * Autorise a envoyer les en-tetes suivant
         */
        response.addHeader("Access-Control-Expose-Headers",
                "Access-Control-Allow-Origin, " +
                        "Access-Control-Allow-Credentials, " +
                        "Authorization");


        // si requete avec option , pas de token a vérifier
        if (request.getMethod().equals("OPTIONS")) {

            log.info("Requête avec Option : " + HttpServletResponse.SC_OK);
            System.out.println("Response OK : " + HttpServletResponse.SC_OK);
            response.setStatus(HttpServletResponse.SC_OK);
            log.info("**************************************************");

        } else if (request.getServletPath().equals("/refreshToken")) {

            log.info("Requête ne necessitant pas de droits :");
            log.info("Pour la rafraîchissement du token ");
            log.info("**************************************************");

            filterChain.doFilter(request, response);
        } else {

            // recupération du token dans Authorization
            String authorization = request.getHeader(Constant.AUTHORIZATION);

            if (authorization != null && authorization.startsWith(Constant.BEARER)) {

                log.info(" requete pour la creation du token ");

                try {

                    // vérification de la signature du token
                    DecodedJWT decodedJWT = Token_HMAC256.MatchingToken(authorization,
                            Algorithm.HMAC256(Constant.SECRET));

                    // recuperation du username
                    String username = decodedJWT.getSubject();

                    // recup des ROLES dans le revendication
                    String[] roles = decodedJWT.getClaim(Constant.ROLES).asArray(String.class);

                    // convertion des ROLES en type GrantedAuthority
                    Collection<GrantedAuthority> authorities = new ArrayList<>();

                    for (String r : roles) {
                        authorities.add(new SimpleGrantedAuthority(r));
                    }

                    // creation d'un objet user authentification pour valider le droit de passage
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);

                    // authentifie l'utilisateur
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // passe au filtre suivant
                    filterChain.doFilter(request, response);
                    log.info("**************************************************");

                } catch (Exception ex) {

                    log.error("********************* ERROR_MESSAGE message : " + ex.getMessage());
                    log.error("********************* ERROR_MESSAGE Cause : " + ex.getCause());
                    log.error("********************* ERROR_MESSAGE Classe : " + ex.getClass());
                    log.error("********************* ERROR_MESSAGE LocalizedMessage : " + ex.getLocalizedMessage());
                    log.error("********************* ERROR_MESSAGE StackTrace: " + ex.getStackTrace());
                    log.error("********************* ERROR_MESSAGE Nue : " + ex);

                    response.setHeader(Constant.ERROR_MESSAGE, ex.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);

                }

            } else {

                log.info("Accéde a du contenu sans droit d'accés");
                log.info("**************************************************");
                filterChain.doFilter(request, response);

            }
        }
    }
}
