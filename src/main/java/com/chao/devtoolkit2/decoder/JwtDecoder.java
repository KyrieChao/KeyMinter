package com.chao.devtoolkit.decoder;

import com.chao.devtoolkit.core.Jwt;
import com.chao.devtoolkit.dto.JwtFullInfo;
import com.chao.devtoolkit.dto.JwtStandardInfo;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
public class JwtDecoder {

    private static final ObjectMapper objectMapper = createObjectMapper();

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // 配置ObjectMapper忽略未知字段
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        // 允许空字段
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        // 日期格式
        mapper.setDateFormat(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"));
        return mapper;
    }

    /**
     * 解码为包含标准信息和自定义信息的完整对象
     */
    public static <T> T decodeToObject(String token, Class<T> clazz, Jwt jwt) {
        try {
            Claims claims = jwt.decodePayload(token);
            return convertToFullObject(claims, clazz);
        } catch (Exception e) {
            log.error("Failed to decode token to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new RuntimeException("Token decoding failed", e);
        }
    }

    /**
     * 解码为包含标准信息和自定义信息的Map
     */
    public static Map<String, Object> decodeToFullMap(String token, Jwt jwt) {
        try {
            Claims claims = jwt.decodePayload(token);
            return createFullClaimsMap(claims);
        } catch (Exception e) {
            log.error("Failed to decode token to map: {}", e.getMessage());
            throw new RuntimeException("Token decoding failed", e);
        }
    }

    /**
     * 解码并分离标准信息和自定义信息
     */
    public static <T> JwtFullInfo<T> decodeToFullInfo(String token, Class<T> customClaimsClass, Jwt jwt) {
        try {
            Claims claims = jwt.decodePayload(token);

            JwtFullInfo<T> fullInfo = new JwtFullInfo<>();
            fullInfo.setStandardInfo(extractStandardInfo(claims));
            fullInfo.setCustomClaims(convertCustomClaims(claims, customClaimsClass));
            fullInfo.setAllClaims(createFullClaimsMap(claims));
            return fullInfo;
        } catch (Exception e) {
            log.error("Failed to decode token to full info: {}", e.getMessage());
            throw new RuntimeException("Token decoding failed", e);
        }
    }

    /**
     * 安全解码 - 不会抛出异常，返回null
     */
    public static <T> JwtFullInfo<T> decodeToFullInfoSafe(String token, Class<T> customClaimsClass, Jwt jwt) {
        try {
            return decodeToFullInfo(token, customClaimsClass, jwt);
        } catch (Exception e) {
            log.warn("Safe decode failed for token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅提取标准信息
     */
    public static JwtStandardInfo decodeStandardInfo(String token, Jwt jwt) {
        try {
            Claims claims = jwt.decodePayload(token);
            return extractStandardInfo(claims);
        } catch (Exception e) {
            log.error("Failed to decode standard info: {}", e.getMessage());
            throw new RuntimeException("Token decoding failed", e);
        }
    }

    /**
     * 仅提取自定义信息
     */
    public static <T> T decodeCustomClaims(String token, Class<T> customClaimsClass, Jwt jwt) {
        try {
            Claims claims = jwt.decodePayload(token);
            return convertCustomClaims(claims, customClaimsClass);
        } catch (Exception e) {
            log.error("Failed to decode custom claims: {}", e.getMessage());
            throw new RuntimeException("Token decoding failed", e);
        }
    }

    // ========== 私有方法 ==========

    private static JwtStandardInfo extractStandardInfo(Claims claims) {
        return JwtStandardInfo.builder()
                .subject(claims.getSubject())
                .issuer(claims.getIssuer())
                .issuedAt(claims.getIssuedAt())
                .expiration(claims.getExpiration())
                .build();
    }

    @SuppressWarnings("unchecked")
    private static <T> T convertCustomClaims(Claims claims, Class<T> clazz) {
        try {
            Map<String, Object> customClaims = new HashMap<>();
            // 提取自定义声明（排除标准声明）
            claims.forEach((key, value) -> {
                if (!"sub".equals(key) && !"iss".equals(key) &&
                        !"iat".equals(key) && !"exp".equals(key)) {
                    customClaims.put(key, value);
                }
            });
            String json = objectMapper.writeValueAsString(customClaims);
            return objectMapper.readValue(json, clazz);

        } catch (Exception e) {
            throw new RuntimeException("Failed to convert custom claims to " + clazz.getSimpleName(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T convertToFullObject(Claims claims, Class<T> clazz) {
        try {
            Map<String, Object> fullClaims = createCleanFullClaimsMap(claims);
            String json = objectMapper.writeValueAsString(fullClaims);
            return objectMapper.readValue(json, clazz);
        } catch (Exception e) {
            log.error("Failed to convert claims to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new RuntimeException("Failed to convert to " + clazz.getSimpleName(), e);
        }
    }

    /**
     * 创建干净的完整声明Map（不包含重复的JWT标准字段）
     */
    private static Map<String, Object> createCleanFullClaimsMap(Claims claims) {
        Map<String, Object> fullMap = new LinkedHashMap<>();

        // 只使用友好的key名称，避免重复
        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());

        // 自定义信息
        claims.forEach((key, value) -> {
            if (!"sub".equals(key) && !"iss".equals(key) &&
                    !"iat".equals(key) && !"exp".equals(key)) {
                fullMap.put(key, value);
            }
        });

        return fullMap;
    }

    /**
     * 创建包含所有字段的完整Map（用于调试和查看所有信息）
     */
    private static Map<String, Object> createFullClaimsMap(Claims claims) {
        Map<String, Object> fullMap = new LinkedHashMap<>();

        // 标准信息（使用友好的key名称）
        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());

        // 原始的JWT标准声明key
        fullMap.put("sub", claims.getSubject());
        fullMap.put("iss", claims.getIssuer());
        fullMap.put("iat", claims.getIssuedAt());
        fullMap.put("exp", claims.getExpiration());

        // 自定义信息
        claims.forEach((key, value) -> {
            if (!"sub".equals(key) && !"iss".equals(key) &&
                    !"iat".equals(key) && !"exp".equals(key)) {
                fullMap.put(key, value);
            }
        });

        return fullMap;
    }
}