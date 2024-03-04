package com.oauth2.resourceserver.filter.authorization;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

public abstract class JwtAuthorizationFilter extends OncePerRequestFilter {

    private JWSVerifier jwsVerifier;

    public JwtAuthorizationFilter(JWSVerifier jwsVerifier) {
        this.jwsVerifier = jwsVerifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace("Bearer ", "");

        SignedJWT signedJWT;

        try {
            signedJWT = SignedJWT.parse(token);
            boolean verify = signedJWT.verify(jwsVerifier);

            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

            if (verify) {
                String username = jwtClaimsSet.getClaim("username").toString();
                List<String> authority = (List<String>) jwtClaimsSet.getClaim("authority");

                if (username != null) {
                    UserDetails user = User.withUsername(username)
                            .password(UUID.randomUUID().toString())
                            .authorities(authority.get(0))
                            .build();

                    Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

            }

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }

        filterChain.doFilter(request,response);
    }

}
