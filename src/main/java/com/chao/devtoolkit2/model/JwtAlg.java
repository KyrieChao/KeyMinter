package com.chao.devtoolkit.model;

import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum JwtAlg {
    HS256(1, Jwts.SIG.HS256),
    HS384(2, Jwts.SIG.HS384),
    HS512(3, Jwts.SIG.HS512),
    RS256(1, Jwts.SIG.RS256),
    RS384(2, Jwts.SIG.RS384),
    RS512(3, Jwts.SIG.RS512),
    ES256(1, Jwts.SIG.ES256),
    ES384(2, Jwts.SIG.ES384),
    ES512(3, Jwts.SIG.ES512),
    EdDSA(1, Jwts.SIG.EdDSA);

    private final Integer code;
    private final Object alg;
}
