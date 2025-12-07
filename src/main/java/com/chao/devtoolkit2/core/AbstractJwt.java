package com.chao.devtoolkit.core;

import com.chao.devtoolkit.config.JwtProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.Date;
import java.util.Map;

@Getter
@Slf4j
public abstract class AbstractJwt implements Jwt {
    protected Path currentKeyDir;

    @Override
    public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType) {
        validateJwtProperties(properties);
        validateAlgorithmType(algorithmType);
        return generateJwt(properties, customClaims, algorithmType);
    }

    public abstract boolean verifyToken(String token);

    public abstract Claims decodePayload(String token);

    @Override
    public String refreshToken(String token) {
        return null;
    }

    @Override
    public boolean revokeToken(String token) {
        return false;
    }

    @Override
    public boolean manageSecret(String secret) {
        return false;
    }

    public abstract String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Integer algorithmType);

    public abstract String generateJwt(JwtProperties properties, Integer algorithmType);

    protected void validateJwtProperties(JwtProperties properties) {
        if (properties == null) {
            throw new IllegalArgumentException("JwtProperties cannot be null");
        }
        if (StringUtils.isBlank(properties.getSubject())) {
            throw new IllegalArgumentException("JWT subject cannot be null or empty");
        }
        if (properties.getExpiration() == null || properties.getExpiration() <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        if (StringUtils.isBlank(properties.getIssuer())) {
            throw new IllegalArgumentException("JWT issuer cannot be null or empty");
        }
    }

    protected JwtBuilder createJwtBuilder(JwtProperties properties, Map<String, Object> customClaims) {
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .subject(properties.getSubject())
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(new Date(now + properties.getExpiration()));
        if (customClaims != null && !customClaims.isEmpty()) {
            builder.claims(customClaims);
        }
        return builder;
    }

    @Override
    public <T> Map<String, Object> convertToClaimsMap(T customClaims) {
        if (customClaims == null) {
            return null;
        }
        if (customClaims instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) customClaims;
            return map;
        }
        ObjectMapper mapper = new ObjectMapper();
        if (customClaims instanceof String) {
            try {
                return mapper.readValue((String) customClaims,
                        new com.fasterxml.jackson.core.type.TypeReference<>() {
                        });
            } catch (JsonProcessingException e) {
                throw new IllegalArgumentException("Invalid JSON claims string", e);
            }
        }
        try {
            String json = mapper.writeValueAsString(customClaims);
            return mapper.readValue(json,
                    new com.fasterxml.jackson.core.type.TypeReference<>() {
                    });
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to convert object to claims map", e);
        }
    }

    // 新增通用方法
    @Override
    public String getKeyInfo() {
        return "Key directory: " + (currentKeyDir != null ? currentKeyDir.toString() : "Not set");
    }

    @Override
    public Path getKeyPath() {
        return currentKeyDir;
    }

    @Override
    public String getAlgorithmInfo() {
        return "Default algorithm information";
    }

    protected void validateAlgorithmType(Integer algorithmType) {
        if (algorithmType == null) {
            throw new IllegalArgumentException("Algorithm type must be 1 (HS256), 2 (HS384), or 3 (HS512)");
        }
    }

    // 抽象方法，子类实现
    protected abstract MacAlgorithm getSignAlgorithm(Integer algorithmType);

    // 抽象方法，子类实现
    protected abstract String getSecretKey();
}
