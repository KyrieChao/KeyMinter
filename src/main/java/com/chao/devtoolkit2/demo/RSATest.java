package com.chao.devtoolkit2.demo;

import com.chao.devtoolkit2.config.JwtProperties;
import com.chao.devtoolkit2.core.Jwt;
import com.chao.devtoolkit2.crypto.HmacJwt;
import com.chao.devtoolkit2.decoder.JwtDecoder;
import com.chao.devtoolkit2.dto.Algorithm;
import com.chao.devtoolkit2.dto.JwtStandardInfo;
import com.chao.devtoolkit2.model.UserInfo;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class HmacTest {
    public static void main(String[] args) {
//        Jwt test = new HmacJwt("D:\\Lan\\tmp\\hmac-keys");
        Algorithm hmac512 = Algorithm.HMAC512;
        Jwt test = new HmacJwt().autoLoadFirstKey(hmac512);
        String s = test.generateToken(toJwtProperties(), toUserInfo(), hmac512, UserInfo.class);
//        boolean b = test.generateHmacKey(Algorithm.HMAC384, 128);
//        System.out.println(b);
//        System.out.println(test.listHmacKeys());
        System.out.println(s);
        System.out.println(test.getKeyInfo());
//        System.out.println(test.getKeyVersions());
//        System.out.println(test.getAlgorithmInfo());
        UserInfo customClaims = JwtDecoder.decodeCustomClaims(s, test, UserInfo.class);
        JwtStandardInfo decoded = JwtDecoder.decodeStandardInfo(s, test);
        System.out.println(customClaims);
        System.out.println(decoded);
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
