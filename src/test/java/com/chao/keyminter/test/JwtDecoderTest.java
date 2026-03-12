package com.chao.keyminter.test;

import com.chao.keyminter.api.JwtDecoder;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.JwtStandardInfo;
import com.chao.keyminter.domain.model.JwtFullInfo;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;

/**
 * JwtDecoder 单元测试
 * 测试JWT解码功能
 */
@DisplayName("JwtDecoder 测试")
class JwtDecoderTest {

    private JwtAlgo mockJwtAlgo;
    private Claims mockClaims;

    @BeforeEach
    void setUp() {
        mockJwtAlgo = mock(JwtAlgo.class);
        mockClaims = mock(Claims.class);
    }

    // ==================== 解码到对象测试 ====================

    @Nested
    @DisplayName("解码到对象测试")
    class DecodeToObjectTests {

        @Test
        @DisplayName("解码到对象 - 成功")
        void decodeToObject_Success() {
            // 设置mock
            when(mockClaims.getSubject()).thenReturn("test-subject");
            when(mockClaims.getIssuer()).thenReturn("test-issuer");
            when(mockClaims.getIssuedAt()).thenReturn(new Date());
            when(mockClaims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 3600000));
            when(mockClaims.entrySet()).thenReturn(Collections.emptySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Map result = JwtDecoder.decodeToObject("valid-token", Map.class, mockJwtAlgo);

            assertNotNull(result);
            verify(mockJwtAlgo).decodePayload("valid-token");
        }

        @Test
        @DisplayName("解码到对象 - 空Token抛出异常")
        void decodeToObject_EmptyToken_ThrowsException() {
            assertThrows(IllegalArgumentException.class, () ->
                    JwtDecoder.decodeToObject("", Map.class, mockJwtAlgo)
            );

            assertThrows(IllegalArgumentException.class, () ->
                    JwtDecoder.decodeToObject(null, Map.class, mockJwtAlgo)
            );
        }

        @Test
        @DisplayName("解码到对象 - 空算法抛出异常")
        void decodeToObject_NullAlgo_ThrowsException() {
            assertThrows(IllegalArgumentException.class, () ->
                    JwtDecoder.decodeToObject("token", Map.class, null)
            );
        }

        @Test
        @DisplayName("解码到对象 - 解码失败抛出异常")
        void decodeToObject_DecodeFails_ThrowsException() {
            when(mockJwtAlgo.decodePayload("invalid-token"))
                    .thenThrow(new RuntimeException("Decode failed"));

            assertThrows(JwtDecoder.JwtDecodeException.class, () ->
                    JwtDecoder.decodeToObject("invalid-token", Map.class, mockJwtAlgo)
            );
        }
    }

    // ==================== 解码到Map测试 ====================

    @Nested
    @DisplayName("解码到Map测试")
    class DecodeToFullMapTests {

        @Test
        @DisplayName("解码到完整Map - 成功")
        void decodeToFullMap_Success() {
            Date now = new Date();
            Date exp = new Date(System.currentTimeMillis() + 3600000);

            when(mockClaims.getSubject()).thenReturn("test-subject");
            when(mockClaims.getIssuer()).thenReturn("test-issuer");
            when(mockClaims.getIssuedAt()).thenReturn(now);
            when(mockClaims.getExpiration()).thenReturn(exp);
            when(mockClaims.entrySet()).thenReturn(Map.of("custom", (Object) "value").entrySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Map<String, Object> result = JwtDecoder.decodeToFullMap("valid-token", mockJwtAlgo);

            assertNotNull(result);
            assertEquals("test-subject", result.get("subject"));
            assertEquals("test-issuer", result.get("issuer"));
        }

        @Test
        @DisplayName("解码到完整Map - 解码失败抛出异常")
        void decodeToFullMap_DecodeFails_ThrowsException() {
            when(mockJwtAlgo.decodePayload(anyString()))
                    .thenThrow(new RuntimeException("Decode failed"));

            assertThrows(JwtDecoder.JwtDecodeException.class, () ->
                    JwtDecoder.decodeToFullMap("token", mockJwtAlgo)
            );
        }
    }

    // ==================== 解码到完整信息测试 ====================

    @Nested
    @DisplayName("解码到完整信息测试")
    class DecodeToFullInfoTests {

        @Test
        @DisplayName("解码到完整信息 - 成功")
        void decodeToFullInfo_Success() {
            Date now = new Date();
            Date exp = new Date(System.currentTimeMillis() + 3600000);

            when(mockClaims.getSubject()).thenReturn("test-subject");
            when(mockClaims.getIssuer()).thenReturn("test-issuer");
            when(mockClaims.getIssuedAt()).thenReturn(now);
            when(mockClaims.getExpiration()).thenReturn(exp);
            when(mockClaims.entrySet()).thenReturn(Map.of("role", (Object) "admin").entrySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);
            JwtFullInfo<Map> result = JwtDecoder.decodeToFullInfo(
                    "valid-token", Map.class, mockJwtAlgo
            );

            assertNotNull(result);
            assertNotNull(result.getStandardInfo());
            assertEquals("test-subject", result.getStandardInfo().getSubject());
            assertNotNull(result.getAllClaims());
        }

        @Test
        @DisplayName("安全解码到完整信息 - 成功")
        void decodeToFullInfoSafe_Success() {
            Date now = new Date();
            Date exp = new Date(System.currentTimeMillis() + 3600000);

            when(mockClaims.getSubject()).thenReturn("test-subject");
            when(mockClaims.getIssuer()).thenReturn("test-issuer");
            when(mockClaims.getIssuedAt()).thenReturn(now);
            when(mockClaims.getExpiration()).thenReturn(exp);
            when(mockClaims.entrySet()).thenReturn(Collections.emptySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            JwtFullInfo<Map> result = JwtDecoder.decodeToFullInfoSafe(
                    "valid-token", Map.class, mockJwtAlgo
            );

            assertNotNull(result);
        }

        @Test
        @DisplayName("安全解码到完整信息 - 无效参数返回null")
        void decodeToFullInfoSafe_InvalidParams_ReturnsNull() {
            assertNull(JwtDecoder.decodeToFullInfoSafe(null, Map.class, mockJwtAlgo));
            assertNull(JwtDecoder.decodeToFullInfoSafe("token", null, mockJwtAlgo));
            assertNull(JwtDecoder.decodeToFullInfoSafe("token", Map.class, null));
        }

        @Test
        @DisplayName("安全解码到完整信息 - 解码失败返回null")
        void decodeToFullInfoSafe_DecodeFails_ReturnsNull() {
            when(mockJwtAlgo.decodePayload(anyString()))
                    .thenThrow(new RuntimeException("Decode failed"));

            assertNull(JwtDecoder.decodeToFullInfoSafe("token", Map.class, mockJwtAlgo));
        }
    }

    // ==================== 解码标准信息测试 ====================

    @Nested
    @DisplayName("解码标准信息测试")
    class DecodeStandardInfoTests {

        @Test
        @DisplayName("解码标准信息 - 成功")
        void decodeStandardInfo_Success() {
            Date now = new Date();
            Date exp = new Date(System.currentTimeMillis() + 3600000);

            when(mockClaims.getSubject()).thenReturn("test-subject");
            when(mockClaims.getIssuer()).thenReturn("test-issuer");
            when(mockClaims.getIssuedAt()).thenReturn(now);
            when(mockClaims.getExpiration()).thenReturn(exp);
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            JwtStandardInfo result = JwtDecoder.decodeStandardInfo("valid-token", mockJwtAlgo);

            assertNotNull(result);
            assertEquals("test-subject", result.getSubject());
            assertEquals("test-issuer", result.getIssuer());
            assertEquals(now, result.getIssuedAt());
            assertEquals(exp, result.getExpiration());
        }

        @Test
        @DisplayName("解码标准信息 - 解码失败返回null")
        void decodeStandardInfo_DecodeFails_ReturnsNull() {
            when(mockJwtAlgo.decodePayload(anyString()))
                    .thenThrow(new RuntimeException("Decode failed"));

            assertNull(JwtDecoder.decodeStandardInfo("token", mockJwtAlgo));
        }
    }

    // ==================== 解码时间测试 ====================

    @Nested
    @DisplayName("解码时间测试")
    class DecodeTimeTests {

        @Test
        @DisplayName("解码过期时间 - 成功")
        void decodeExpiration_Success() {
            Date exp = new Date(System.currentTimeMillis() + 3600000);
            when(mockClaims.getExpiration()).thenReturn(exp);
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Date result = JwtDecoder.decodeExpiration("valid-token", mockJwtAlgo);

            assertNotNull(result);
            assertEquals(exp, result);
        }

        @Test
        @DisplayName("解码过期时间 - 空Token返回null")
        void decodeExpiration_EmptyToken_ReturnsNull() {
            assertNull(JwtDecoder.decodeExpiration(null, mockJwtAlgo));
            assertNull(JwtDecoder.decodeExpiration("", mockJwtAlgo));
        }

        @Test
        @DisplayName("解码签发时间 - 成功")
        void decodeIssuedAt_Success() {
            Date iat = new Date();
            when(mockClaims.getIssuedAt()).thenReturn(iat);
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Date result = JwtDecoder.decodeIssuedAt("valid-token", mockJwtAlgo);

            assertNotNull(result);
            assertEquals(iat, result);
        }

        @Test
        @DisplayName("解码签发时间 - 空Token返回null")
        void decodeIssuedAt_EmptyToken_ReturnsNull() {
            assertNull(JwtDecoder.decodeIssuedAt(null, mockJwtAlgo));
            assertNull(JwtDecoder.decodeIssuedAt("", mockJwtAlgo));
        }
    }

    // ==================== 解码自定义claims测试 ====================

    @Nested
    @DisplayName("解码自定义claims测试")
    class DecodeCustomClaimsTests {

        @Test
        @DisplayName("解码自定义claims - 成功")
        void decodeCustomClaims_Success() {
            when(mockClaims.entrySet()).thenReturn(Map.of("role", (Object) "admin").entrySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Map result = JwtDecoder.decodeCustomClaims(
                    "valid-token", mockJwtAlgo, Map.class
            );

            assertNotNull(result);
        }

        @Test
        @DisplayName("解码自定义claims - 解码失败返回null")
        void decodeCustomClaims_DecodeFails_ReturnsNull() {
            when(mockJwtAlgo.decodePayload(anyString()))
                    .thenThrow(new RuntimeException("Decode failed"));

            assertNull(JwtDecoder.decodeCustomClaims("token", mockJwtAlgo, Map.class));
        }

        @Test
        @DisplayName("安全解码自定义claims - 成功")
        void decodeCustomClaimsSafe_Success() {
            when(mockClaims.entrySet()).thenReturn(Map.of("role", (Object) "admin").entrySet());
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            Map result = JwtDecoder.decodeCustomClaimsSafe(
                    "valid-token", mockJwtAlgo, Map.class
            );

            assertNotNull(result);
        }

        @Test
        @DisplayName("安全解码自定义claims - 无效参数返回null")
        void decodeCustomClaimsSafe_InvalidParams_ReturnsNull() {
            assertNull(JwtDecoder.decodeCustomClaimsSafe(null, mockJwtAlgo, Map.class));
            assertNull(JwtDecoder.decodeCustomClaimsSafe("token", null, Map.class));
            assertNull(JwtDecoder.decodeCustomClaimsSafe("token", mockJwtAlgo, null));
        }
    }

    // ==================== Token可解码性测试 ====================

    @Nested
    @DisplayName("Token可解码性测试")
    class TokenDecodabilityTests {

        @Test
        @DisplayName("Token可解码 - 有效Token")
        void isTokenDecodable_ValidToken_ReturnsTrue() {
            when(mockJwtAlgo.decodePayload("valid-token")).thenReturn(mockClaims);

            assertTrue(JwtDecoder.isTokenDecodable("valid-token", mockJwtAlgo));
        }

        @Test
        @DisplayName("Token可解码 - 无效Token")
        void isTokenDecodable_InvalidToken_ReturnsFalse() {
            when(mockJwtAlgo.decodePayload("invalid-token"))
                    .thenThrow(new RuntimeException("Invalid"));

            assertFalse(JwtDecoder.isTokenDecodable("invalid-token", mockJwtAlgo));
        }

        @Test
        @DisplayName("Token可解码 - 空Token返回false")
        void isTokenDecodable_EmptyToken_ReturnsFalse() {
            assertFalse(JwtDecoder.isTokenDecodable(null, mockJwtAlgo));
            assertFalse(JwtDecoder.isTokenDecodable("", mockJwtAlgo));
            assertFalse(JwtDecoder.isTokenDecodable("token", null));
        }
    }

    // ==================== 异常测试 ====================

    @Nested
    @DisplayName("异常测试")
    class ExceptionTests {

        @Test
        @DisplayName("JwtDecodeException - 构造测试")
        void jwtDecodeException_Construction() {
            JwtDecoder.JwtDecodeException ex1 = new JwtDecoder.JwtDecodeException("test message");
            assertEquals("test message", ex1.getMessage());

            Throwable cause = new RuntimeException("cause");
            JwtDecoder.JwtDecodeException ex2 = new JwtDecoder.JwtDecodeException("test message", cause);
            assertEquals("test message", ex2.getMessage());
            assertEquals(cause, ex2.getCause());
        }
    }
}
