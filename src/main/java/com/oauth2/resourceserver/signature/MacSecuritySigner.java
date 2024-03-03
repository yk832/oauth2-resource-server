package com.oauth2.resourceserver.signature;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.UserDetails;

public class MacSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

        // 서명
        MACSigner jwsSigner = new MACSigner(((OctetSequenceKey)jwk).toSecretKey());
        // 토큰 생성
        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
