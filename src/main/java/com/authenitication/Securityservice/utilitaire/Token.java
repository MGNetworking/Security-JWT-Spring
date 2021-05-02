package com.authenitication.Securityservice.utilitaire;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.authenitication.Securityservice.entities.AppRole;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

public class Token {

    /**
     * Créer un Algorithm de type HMAC256.
     *
     * @param secret de type String le clef .
     * @return de type Algorithme
     */
    public static Algorithm createHMAC256(String secret) {
        return Algorithm.HMAC256(secret);
    }

    /**
     * Permet la création d'un token d'accès a parti
     * d'une Collection de type GrantedAuthority .
     *
     * @param username      String le nom de l'utilisateur
     * @param issuer        String de provenance est la requête
     * @param nbMinutes     int le nombre de minute
     * @param authorityList GrantedAuthority Collection de role de l'utilisateur
     * @param algorithm     Algorithm l'algorithm de cryptage
     * @return un objet de type String, le token d'accés.
     */
    public static String accesToken_Gt(String username,
                                       String issuer,
                                       int nbMinutes,
                                       Collection<GrantedAuthority> authorityList,
                                       Algorithm algorithm) {

        String jwtAccessToken = JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System
                        .currentTimeMillis() + nbMinutes * 60 * 1000))
                .withIssuer(issuer)
                .withClaim(Constant.ROLES,
                        authorityList.stream()
                                .map(grantedAuthority -> grantedAuthority
                                        .getAuthority())
                                .collect(Collectors.toList()))
                .sign(algorithm);

        return jwtAccessToken;
    }

    /**
     * Permet la création d'un token d'accès a parti
     * d'une Collection de type AppRole .
     *
     * @param username  String le nom de l'utilisateur.
     * @param issuer    String de provenance est la requête.
     * @param nbMinutes int le nombre de minute.
     * @param AppRole   AppRole Collection de role de l'utilisateur.
     * @param algorithm Algorithm l'algorithm de cryptage.
     * @return un objet de type String, le token d'accés.
     */
    public static String accesToken_Ap(String username,
                                       String issuer,
                                       int nbMinutes,
                                       Collection<AppRole> authorityList,
                                       Algorithm algorithm) {

        String jwtAccessToken = JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System
                        .currentTimeMillis() + nbMinutes * 60 * 1000))
                .withIssuer(issuer)
                .withClaim(Constant.ROLES,
                        authorityList.stream()
                                .map(grantedAuthority -> grantedAuthority
                                        .getRoleName())
                                .collect(Collectors.toList()))
                .sign(algorithm);

        return jwtAccessToken;
    }

    /**
     * Permet la création d'un token de rafraîchissement.
     *
     * @param username  String le nom de l'utilisateur.
     * @param issuer    String de provenance est la requête.
     * @param nbMinutes int le nombre de minute.
     * @param algorithm Algorithm l'algorithm de cryptage.
     * @return un objet string le token de rafraîchissement.
     */
    public static String refreshToken(String Username,
                                      String issuer,
                                      int nbMinutes,
                                      Algorithm algorithm) {

        String jwtRefreshToken = JWT.create()
                .withSubject(Username)
                .withExpiresAt(new Date(System.currentTimeMillis() +
                        nbMinutes * 60 * 1000))
                .withIssuer(issuer)
                .sign(algorithm);


        return jwtRefreshToken;
    }

    /**
     * Permet de vérifier la signature du JWT token correspond bien a celle émise.
     *
     * @param autorisation String contenant le token
     * @param algorithm
     * @return objet de type DecodedJWT
     */
    public static DecodedJWT MatchingToken(String autorisation, Algorithm algorithm) {

        // recup du token sans le préfix Bearer
        String jwt = autorisation.substring(Constant.BEARER.length());

        // création de la verification de la signature du token
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();

        // verification du token
        return jwtVerifier.verify(jwt);

    }
}
