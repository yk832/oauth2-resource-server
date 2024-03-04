package com.oauth2.resourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 토큰 발행
 *
 * SecuritySigner : MAC, RSA 존재
 */
public abstract class SecuritySigner {

    public abstract String getJwtToken(UserDetails user, JWK jwk) throws JOSEException;

    public String getJwtTokenInternal(JWSSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {
        //JWT 헤더
        JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm()).keyID(jwk.getKeyID()).build();
        List<String> authority = user.getAuthorities().stream().map(m -> m.getAuthority()).collect(Collectors.toList());
        // payload
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("http://localhost:8080")
                .claim("username", user.getUsername())
                .claim("authority", authority)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000 * 5))
            .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwsSigner);
        return signedJWT.serialize();
    }
}
