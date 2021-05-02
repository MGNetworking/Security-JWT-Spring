package com.authenitication.Securityservice.security;

import com.authenitication.Securityservice.entities.AppUser;
import com.authenitication.Securityservice.filtres.JwtAuthentificationFiltre;
import com.authenitication.Securityservice.filtres.JwtAutorisationFiltre;
import com.authenitication.Securityservice.service.CompteService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private CompteService compteService;

    /**
     * Methode de configuration qui fait parti du mecanisme de Spring security.
     * Elle permet la recherche en base de données de l'utilisateur et de ces droits
     * d'accés au travers de ces ROLES .
     * <p>
     * Les ROLES d'un utilisateur données accés au espace accordé par ces ROLES dans le programme.
     * <p>
     * Une Fois l'utilisateur et les ROLES trouvés, renvoi a la methode successful Authentication
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

                log.info("**************************************************");
                log.info("Requête de utilisateur qui cherche a s'authentifier");
                AppUser appUser = compteService.loadUserByName(username);

                log.info("Recupération des ROLES de l'utilisateur");
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getListeRoles().forEach(appRole -> {

                    authorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));

                });
                log.info("**************************************************");
                return new User(appUser.getFirstname(), appUser.getPassword(), authorities);
            }
        });

    }

    /**
     * Methode permet la configuration de Spring Sécurity. Actuellement paramétré pour être
     * utilisé sans état (stateless).
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();

        // parti a login ne néssecite pas d'authentification
        http.authorizeRequests().antMatchers("/login/**", "/refreshToken/**").permitAll();

        // tout les requêtes nécessite une authentification
        http.authorizeRequests().anyRequest().authenticated();

        // Intergration des filtres d'authentification et d'autorisation
        http.addFilter(new JwtAuthentificationFiltre(authenticationManagerBean()));
        http.addFilterBefore(new JwtAutorisationFiltre(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
