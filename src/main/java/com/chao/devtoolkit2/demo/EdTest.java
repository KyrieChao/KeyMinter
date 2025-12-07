package com.chao.devtoolkit2.demo;

import com.chao.devtoolkit2.config.JwtProperties;
import com.chao.devtoolkit2.core.Jwt;
import com.chao.devtoolkit2.crypto.EcdsaJwt;
import com.chao.devtoolkit2.crypto.HmacJwt;
import com.chao.devtoolkit2.decoder.JwtDecoder;
import com.chao.devtoolkit2.dto.Algorithm;
import com.chao.devtoolkit2.dto.JwtStandardInfo;
import com.chao.devtoolkit2.model.UserInfo;

import java.io.IOException;

public class ESTest {
    public static void main(String[] args) {
        Algorithm es = Algorithm.ES256;
        Jwt test = new EcdsaJwt().autoLoadFirstKey(es, false);
//        boolean b = test.generateKeyPair(es);
//        System.out.println(b);
//        String s = test.generateToken(toJwtProperties(), toUserInfo(), es, UserInfo.class);
//        System.out.println(s);
        System.out.println(test.getKeyInfo());
//        System.out.println(test.listRSAKeys());
        System.out.println(test.getKeyVersions());
//        UserInfo customClaims = JwtDecoder.decodeCustomClaims(s, test, UserInfo.class);
//        JwtStandardInfo decoded = JwtDecoder.decodeStandardInfo(s, test);
//        System.out.println(customClaims);
//        System.out.println(decoded);
    }

    private static UserInfo toUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername("username");
        userInfo.setRole("admin");
        userInfo.setAge(18);
        userInfo.setActive(true);
        userInfo.setPreferences(new UserInfo.Preferences("dark", "en"));
        return userInfo;
    }

    private static JwtProperties toJwtProperties() {
        JwtProperties properties = new JwtProperties();
        properties.setSubject("sub");
        properties.setIssuer("issuer");
        properties.setExpiration(3600L);
        return properties;
    }
}
