package com.chao.devtoolkit.core;

import com.chao.devtoolkit.config.JwtProperties;
import io.jsonwebtoken.Claims;

import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;

public interface Jwt {
    // 核心JWT操作
    String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType);

    boolean verifyToken(String token);

    Claims decodePayload(String token);

    // 刷新 Token
    String refreshToken(String token);

    // 撤销或黑名单管理
    boolean revokeToken(String token);

    // 密钥管理
    boolean manageSecret(String secret);

    // 密钥对管理（用于RSA算法）
    default boolean generateKeyPair(Integer keySize) {
        throw new UnsupportedOperationException("Key pair generation not supported");
    }

    default boolean generateKeyPair(Integer keySize, String filename) {
        throw new UnsupportedOperationException("Key pair generation not supported");
    }
    default boolean generateHmacKeyPair(Integer keySize,Integer len) {
        throw new UnsupportedOperationException("Key pair generation not supported");
    }

    default boolean generateHmacKeyPair(Integer keySize, String filename,Integer len) {
        throw new UnsupportedOperationException("Key pair generation not supported");
    }

    default PublicKey getPublicKey() {
        throw new UnsupportedOperationException("Public key not available");
    }

    default String getCurveInfo(Integer algorithmType) {
        throw new UnsupportedOperationException("Curve information not available");
    }

    default boolean generateAllKeyPairs() {
        throw new UnsupportedOperationException("Key pair generation not supported for all algorithms");
    }

    default String getKeyInfo(Integer algorithmType) {
        throw new UnsupportedOperationException("Key information not available");
    }

    // 新增：获取密钥信息的方法
    default String getKeyInfo() {
        throw new UnsupportedOperationException("Key information not available");
    }

    default Path getKeyPath() {
        throw new UnsupportedOperationException("Key path not available");
    }

    default String getAlgorithmInfo() {
        throw new UnsupportedOperationException("Algorithm information not available");
    }

    // 新增泛型版本
    default <T> String generateToken(JwtProperties properties, T customClaims, Integer algorithmType, Class<T> claimsType) {
        Map<String, Object> claimsMap = convertToClaimsMap(customClaims);
        return generateToken(properties, claimsMap, algorithmType);
    }

    // 默认的转换方法
    default <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        return null;
    }


    default void HmacLen(Integer len) {
    }
}
