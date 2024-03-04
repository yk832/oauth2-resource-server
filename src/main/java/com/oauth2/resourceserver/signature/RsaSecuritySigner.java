package com.oauth2.resourceserver.signature;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

public class RsaSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

        // 서명
        RSASSASigner jwsSigner = new RSASSASigner(((RSAKey)jwk).toRSAPrivateKey());
        // 토큰 생성
        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
