package com.chao.devtoolkit.util;

import com.chao.devtoolkit.config.JwtProperties;
import com.chao.devtoolkit.core.Jwt;
import com.chao.devtoolkit.decoder.JwtDecoder;
import com.chao.devtoolkit.dto.JwtInfo;
import com.chao.devtoolkit.dto.JwtStandardInfo;
import com.chao.devtoolkit.factory.JwtFactory;
import com.chao.devtoolkit.model.UserInfo;

import java.util.Objects;

public class JwtUtil {
    private static final Jwt t = JwtFactory.createHmacJwt();
    private static final int DEFAULT_SECRET_LENGTH = 64;

    /**
     * 生成密钥
     */
    private static boolean createHmacKey(Integer algorithmType, Integer length) {
        return t.generateHmacKeyPair(algorithmType, Objects.requireNonNullElse(length, DEFAULT_SECRET_LENGTH));
    }

    private static boolean createKey(Integer algorithmType) {
        return t.generateKeyPair(algorithmType);
    }
    private static boolean createKey(Integer algorithmType,String filename) {
        return t.generateKeyPair(algorithmType, filename);
    }

    /**
     * 生成Token 有自定义信息
     */
    private static String generateToken(JwtInfo t, UserInfo userInfo) {
        JwtProperties props = JwtProperties.builder()
                .subject(t.getSubject())
                .issuer(t.getIssuer())
                .expiration(t.getExpiration())
                .build();
        return JwtUtil.t.generateToken(props, userInfo, 1, UserInfo.class);
    }

    private static String generateToken(JwtInfo t) {
        JwtProperties props = JwtProperties.builder()
                .subject(t.getSubject())
                .issuer(t.getIssuer())
                .expiration(t.getExpiration())
                .build();
        return JwtUtil.t.generateToken(props, null, 1, UserInfo.class);
    }

    /**
     * 获取标准信息
     */
    private static <T> JwtStandardInfo StandardInfo(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfo(token, clazz, t).getStandardInfo();
    }

    /**
     * 获取自定义信息
     */
    private static <T> T CustomClaimInfo(String token, Class<T> clazz) {
        return JwtDecoder.decodeToFullInfo(token, clazz, t).getCustomClaims();
    }

    /**
     * 验证Token是否有效
     */
    private static boolean isValidToken(String token) {
        return t.verifyToken(token);
    }
}
