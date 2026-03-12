package com.chao.keyminter.api;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.Claims;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.JwtFullInfo;
import com.chao.keyminter.domain.model.JwtStandardInfo;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

/**
 * JWT解码工具类
 * 提供多种JWT解码方式
 */
@Slf4j
@UtilityClass
public class JwtDecoder {
    private static final ObjectMapper OBJECT_MAPPER = createObjectMapper();
    private static final Set<String> STANDARD_CLAIMS = Set.of("sub", "iss", "iat", "exp", "jti", "aud", "nbf");

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        return mapper;
    }

    /**
     * 解码Token为指定类型的对象
     */
    public static <T> T decodeToObject(String token, Class<T> clazz, JwtAlgo jwtAlgo) {
        validateParameters(token, jwtAlgo);
        Objects.requireNonNull(clazz, "Class type cannot be null");

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return convertToFullObject(claims, clazz);
        } catch (Exception e) {
            log.error("Failed to decode token to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new JwtDecodeException("Failed to decode token to " + clazz.getSimpleName(), e);
        }
    }

    /**
     * 解码Token为完整Map
     */
    public static Map<String, Object> decodeToFullMap(String token, JwtAlgo jwtAlgo) {
        validateParameters(token, jwtAlgo);

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return createFullClaimsMap(claims);
        } catch (Exception e) {
            log.error("Failed to decode token to map: {}", e.getMessage());
            throw new JwtDecodeException("Failed to decode token to map", e);
        }
    }

    /**
     * 解码Token为完整信息对象
     */
    public static <T> JwtFullInfo<T> decodeToFullInfo(String token, Class<T> customClaimsClass, JwtAlgo jwtAlgo) {
        validateParameters(token, jwtAlgo);
        Objects.requireNonNull(customClaimsClass, "Custom claims class cannot be null");

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            JwtFullInfo<T> fullInfo = new JwtFullInfo<>();
            fullInfo.setStandardInfo(extractStandardInfo(claims));
            fullInfo.setCustomClaims(convertCustomClaims(claims, customClaimsClass));
            fullInfo.setAllClaims(createFullClaimsMap(claims));
            return fullInfo;
        } catch (Exception e) {
            log.error("Failed to decode token to full info: {}", e.getMessage());
            throw new JwtDecodeException("Failed to decode token to full info", e);
        }
    }

    /**
     * 安全解码Token为完整信息对象（不抛出异常）
     */
    public static <T> JwtFullInfo<T> decodeToFullInfoSafe(String token, Class<T> customClaimsClass, JwtAlgo jwtAlgo) {
        if (StringUtils.isBlank(token) || jwtAlgo == null || customClaimsClass == null) {
            log.error("Safe decode failed: invalid parameters");
            return null;
        }
        try {
            return decodeToFullInfo(token, customClaimsClass, jwtAlgo);
        } catch (Exception e) {
            log.error("Safe decode failed for token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅解码标准信息
     */
    public static JwtStandardInfo decodeStandardInfo(String token, JwtAlgo jwtAlgo) {
        validateParameters(token, jwtAlgo);
        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return extractStandardInfo(claims);
        } catch (Exception e) {
            log.error("Failed to decode standard info: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅解码expiration
     */
    public static Date decodeExpiration(String token, JwtAlgo jwtAlgo) {
        if (StringUtils.isBlank(token) || jwtAlgo == null) {
            return null;
        }

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return claims.getExpiration();
        } catch (Exception e) {
            log.debug("Failed to decode expiration: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅解码IssuedAt
     */
    public static Date decodeIssuedAt(String token, JwtAlgo jwtAlgo) {
        if (StringUtils.isBlank(token) || jwtAlgo == null) {
            return null;
        }

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return claims.getIssuedAt();
        } catch (Exception e) {
            log.debug("Failed to decode issued at: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅解码自定义声明
     */
    public static <T> T decodeCustomClaims(String token, JwtAlgo jwtAlgo, Class<T> customClaimsClass) {
        validateParameters(token, jwtAlgo);
        Objects.requireNonNull(customClaimsClass, "Custom claims class cannot be null");

        try {
            Claims claims = jwtAlgo.decodePayload(token);
            return convertCustomClaims(claims, customClaimsClass);
        } catch (Exception e) {
            log.error("Failed to decode custom claims: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 安全解码自定义声明（不抛出异常）
     */
    public static <T> T decodeCustomClaimsSafe(String token, JwtAlgo jwtAlgo, Class<T> customClaimsClass) {
        if (StringUtils.isBlank(token) || jwtAlgo == null || customClaimsClass == null) {
            return null;
        }

        try {
            return decodeCustomClaims(token, jwtAlgo, customClaimsClass);
        } catch (Exception e) {
            log.debug("Safe decode custom claims failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 验证Token是否有效且可解码
     */
    public static boolean isTokenDecodable(String token, JwtAlgo jwtAlgo) {
        if (StringUtils.isBlank(token) || jwtAlgo == null) {
            return false;
        }

        try {
            jwtAlgo.decodePayload(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ========== 私有方法 ==========

    /**
     * 验证JWT令牌和算法参数的有效性
     *
     * @param token   JWT令牌字符串，不能为空或null
     * @param jwtAlgo JWT算法实例，不能为null
     * @throws IllegalArgumentException 当token为空或null，或jwtAlgo为null时抛出
     */
    private static void validateParameters(String token, JwtAlgo jwtAlgo) {
        // 检查token是否为空或null
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        // 检查jwtAlgo是否为null
        if (jwtAlgo == null) {
            throw new IllegalArgumentException("JwtAlgo instance cannot be null");
        }
    }

    private static JwtStandardInfo extractStandardInfo(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        return JwtStandardInfo.builder()
                .subject(claims.getSubject())
                .issuer(claims.getIssuer())
                .issuedAt(claims.getIssuedAt())
                .expiration(claims.getExpiration())
                .build();
    }

    @SuppressWarnings("unchecked")
    private static <T> T convertCustomClaims(Claims claims, Class<T> clazz) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        Objects.requireNonNull(clazz, "Class type cannot be null");

        try {
            Map<String, Object> customClaims = claims.entrySet().stream()
                    .filter(entry -> !STANDARD_CLAIMS.contains(entry.getKey()))
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (v1, v2) -> v1,
                            LinkedHashMap::new
                    ));

            if (customClaims.isEmpty() && Map.class.isAssignableFrom(clazz)) {
                return (T) customClaims;
            }

            return OBJECT_MAPPER.convertValue(customClaims, clazz);
        } catch (Exception e) {
            throw new JwtDecodeException("Failed to convert custom claims to " + clazz.getSimpleName(), e);
        }
    }

    private static <T> T convertToFullObject(Claims claims, Class<T> clazz) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        Objects.requireNonNull(clazz, "Class type cannot be null");

        try {
            Map<String, Object> fullClaims = createCleanFullClaimsMap(claims);
            return OBJECT_MAPPER.convertValue(fullClaims, clazz);
        } catch (Exception e) {
            log.error("Failed to convert claims to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new JwtDecodeException("Failed to convert claims to " + clazz.getSimpleName(), e);
        }
    }

    private static Map<String, Object> createCleanFullClaimsMap(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        Map<String, Object> fullMap = new LinkedHashMap<>();

        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());

        claims.forEach((key, value) -> {
            if (!STANDARD_CLAIMS.contains(key)) {
                fullMap.put(key, value);
            }
        });

        return fullMap;
    }

    private static Map<String, Object> createFullClaimsMap(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        Map<String, Object> fullMap = new LinkedHashMap<>();
        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());
        fullMap.putAll(claims);
        return fullMap;
    }

    /**
     * JWT解码异常
     */
    public static class JwtDecodeException extends RuntimeException {
        public JwtDecodeException(String message) {
            super(message);
        }

        public JwtDecodeException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
