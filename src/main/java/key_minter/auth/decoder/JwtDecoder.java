package key_minter.auth.decoder;

import key_minter.auth.core.Jwt;
import key_minter.model.dto.JwtFullInfo;
import key_minter.model.dto.JwtStandardInfo;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.jsonwebtoken.Claims;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.text.SimpleDateFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JWT解码工具类
 * 提供多种JWT解码方式
 */
@Slf4j
@UtilityClass
public class JwtDecoder {
    private static final ObjectMapper OBJECT_MAPPER = createObjectMapper();
    private static final Set<String> STANDARD_CLAIMS = Set.of("sub", "iss", "iat", "exp");
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    // 错误消息常量
    private static final String DECODE_FAILED_MSG = "Token decoding failed";
    private static final String CONVERSION_FAILED_MSG = "Failed to convert to ";

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.setDateFormat(DATE_FORMAT);
        return mapper;
    }

    /**
     * 解码Token为指定类型的对象
     */
    public static <T> T decodeToObject(String token, Class<T> clazz, Jwt jwt) {
        validateParameters(token, jwt);
        try {
            Claims claims = jwt.decodePayload(token);
            return convertToFullObject(claims, clazz);
        } catch (Exception e) {
            log.error("Failed to decode token to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new RuntimeException(DECODE_FAILED_MSG, e);
        }
    }

    /**
     * 解码Token为完整Map
     */
    public static Map<String, Object> decodeToFullMap(String token, Jwt jwt) {
        validateParameters(token, jwt);
        try {
            Claims claims = jwt.decodePayload(token);
            return createFullClaimsMap(claims);
        } catch (Exception e) {
            log.error("Failed to decode token to map: {}", e.getMessage());
            throw new RuntimeException(DECODE_FAILED_MSG, e);
        }
    }

    /**
     * 解码Token为完整信息对象
     */
    public static <T> JwtFullInfo<T> decodeToFullInfo(String token, Class<T> customClaimsClass, Jwt jwt) {
        validateParameters(token, jwt);
        try {
            Claims claims = jwt.decodePayload(token);

            JwtFullInfo<T> fullInfo = new JwtFullInfo<>();
            fullInfo.setStandardInfo(extractStandardInfo(claims));
            fullInfo.setCustomClaims(convertCustomClaims(claims, customClaimsClass));
            fullInfo.setAllClaims(createFullClaimsMap(claims));
            return fullInfo;
        } catch (Exception e) {
            log.error("Failed to decode token to full info: {}", e.getMessage());
            throw new RuntimeException(DECODE_FAILED_MSG, e);
        }
    }

    /**
     * 安全解码Token为完整信息对象（不抛出异常）
     */
    public static <T> JwtFullInfo<T> decodeToFullInfoSafe(String token, Class<T> customClaimsClass, Jwt jwt) {
        if (token == null || token.trim().isEmpty() || jwt == null) {
            log.warn("Safe decode failed: token or jwt is null");
            return null;
        }
        try {
            return decodeToFullInfo(token, customClaimsClass, jwt);
        } catch (Exception e) {
            log.warn("Safe decode failed for token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 仅解码标准信息
     */
    public static JwtStandardInfo decodeStandardInfo(String token, Jwt jwt) {
        validateParameters(token, jwt);
        try {
            Claims claims = jwt.decodePayload(token);
            return extractStandardInfo(claims);
        } catch (Exception e) {
            log.error("Failed to decode standard info: {}", e.getMessage());
//            throw new RuntimeException(DECODE_FAILED_MSG, e);
            return null;
        }
    }

    /**
     * 仅解码自定义声明
     */
    public static <T> T decodeCustomClaims(String token, Jwt jwt, Class<T> customClaimsClass) {
        validateParameters(token, jwt);
        try {
            Claims claims = jwt.decodePayload(token);
            return convertCustomClaims(claims, customClaimsClass);
        } catch (Exception e) {
            log.error("Failed to decode custom claims: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 安全解码自定义声明（不抛出异常）
     */
    public static <T> T decodeCustomClaimsSafe(String token, Jwt jwt, Class<T> customClaimsClass) {
        if (token == null || token.trim().isEmpty() || jwt == null) {
            return null;
        }
        try {
            return decodeCustomClaims(token, jwt, customClaimsClass);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 验证Token是否有效且可解码
     */
    public static boolean isTokenDecodable(String token, Jwt jwt) {
        if (token == null || token.trim().isEmpty() || jwt == null) {
            return false;
        }
        try {
            jwt.decodePayload(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ========== 私有方法 ==========

    private static void validateParameters(String token, Jwt jwt) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        if (jwt == null) {
            throw new IllegalArgumentException("Jwt instance cannot be null");
        }
    }

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
            Map<String, Object> customClaims = claims.entrySet().stream()
                    .filter(entry -> !STANDARD_CLAIMS.contains(entry.getKey()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            // 如果自定义声明为空且目标类型是Map，直接返回空Map
            if (customClaims.isEmpty() && Map.class.isAssignableFrom(clazz)) {
                return (T) customClaims;
            }

            return OBJECT_MAPPER.convertValue(customClaims, clazz);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert custom claims to " + clazz.getSimpleName(), e);
        }
    }

    private static <T> T convertToFullObject(Claims claims, Class<T> clazz) {
        try {
            Map<String, Object> fullClaims = createCleanFullClaimsMap(claims);
            return OBJECT_MAPPER.convertValue(fullClaims, clazz);
        } catch (Exception e) {
            log.error("Failed to convert claims to {}: {}", clazz.getSimpleName(), e.getMessage());
            throw new RuntimeException(CONVERSION_FAILED_MSG + clazz.getSimpleName(), e);
        }
    }

    private static Map<String, Object> createCleanFullClaimsMap(Claims claims) {
        Map<String, Object> fullMap = new LinkedHashMap<>();

        // 标准信息使用友好名称
        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());

        // 自定义声明
        claims.forEach((key, value) -> {
            if (!STANDARD_CLAIMS.contains(key)) {
                fullMap.put(key, value);
            }
        });

        return fullMap;
    }

    private static Map<String, Object> createFullClaimsMap(Claims claims) {
        Map<String, Object> fullMap = new LinkedHashMap<>();
        // 标准信息（友好名称）
        fullMap.put("subject", claims.getSubject());
        fullMap.put("issuer", claims.getIssuer());
        fullMap.put("issuedAt", claims.getIssuedAt());
        fullMap.put("expiration", claims.getExpiration());
        // 原始JWT声明
        fullMap.putAll(claims);
        return fullMap;
    }
}