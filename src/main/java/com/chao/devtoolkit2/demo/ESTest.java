package com.chao.devtoolkit2.demo;

import com.chao.devtoolkit2.config.JwtProperties;
import com.chao.devtoolkit2.core.Jwt;
import com.chao.devtoolkit2.crypto.EcdsaJwt;
import com.chao.devtoolkit2.crypto.EddsaJwt;
import com.chao.devtoolkit2.crypto.HmacJwt;
import com.chao.devtoolkit2.crypto.RsaJwt;
import com.chao.devtoolkit2.decoder.JwtDecoder;
import com.chao.devtoolkit2.dto.Algorithm;
import com.chao.devtoolkit2.dto.JwtStandardInfo;
import com.chao.devtoolkit2.dto.KeyVersion;
import com.chao.devtoolkit2.factory.JwtFactory;
import com.chao.devtoolkit2.model.UserInfo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.stream.Collectors;

public class demo {
    public static void main(String[] args) throws IOException {
        Algorithm m = Algorithm.HMAC256;
        Jwt jwt = new HmacJwt().autoLoadFirstKey(m, false);
//        Jwt jwt = JwtFactory.get(m);
//        boolean b = new HmacJwt().generateHmacKey(m, 128);
//        jwt.setActiveKey("ES256-v20251204-153729-cf551c7c");
//        System.out.println(jwt);
//        HmacJwt jwt = new HmacJwt().autoLoadFirstKey();
//        String token = jwt.generateToken(toJwtProperties(), toUserInfo(), m, UserInfo.class);

//        String token2 = new EcdsaJwt().autoLoadFirstKey().generateToken(toJwtProperties(), toUserInfo(), Algorithm.ES256, UserInfo.class);
//        System.out.println(token);
//        System.out.println(token2);
        System.out.println(jwt.getKeyVersions(m));
        System.out.println(jwt.getKeyInfo());
        System.out.println(jwt.getActiveKeyId());
//        System.out.println(token);
//        System.out.println(b);
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
