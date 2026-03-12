package com.chao.keyminter.test;

import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/**
 * RsaJwt 单元测试
 * 测试RSA算法的完整功能
 */
@DisplayName("RsaJwt 测试")
class RsaJwtTest {

    @TempDir
    Path tempDir;

    private KeyMinterProperties properties;
    private KeyMinter keyMinter;
    private JwtFactory factory;

    @BeforeEach
    void setUp() {
        properties = new KeyMinterProperties();
        properties.setEnableRotation(true);
        properties.setKeyDir(tempDir.toString());
        factory = new JwtFactory();
        factory.setProperties(properties);
        keyMinter = new KeyMinter(factory);
    }

    @AfterEach
    void tearDown() {
        if (keyMinter != null) keyMinter.close();
        if (factory != null) factory.close();
    }

    private JwtProperties createValidJwtProperties() {
        return JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
    }

    @Nested
    @DisplayName("密钥对生成测试")
    class KeyPairGenerationTests {

        @Test
        @DisplayName("生成RSA密钥对 - RS256成功")
        void generateKeyPair_RS256_Success() {
            boolean result = keyMinter.createKeyPair(Algorithm.RSA256);
            assertTrue(result);
            assertTrue(keyMinter.switchTo(Algorithm.RSA256, null, null, true));
            assertTrue(keyMinter.keyPairExists());
            assertNotNull(keyMinter.getActiveKeyId());
            assertNotNull(keyMinter.getCurrentKey());
        }

        @Test
        @DisplayName("生成RSA密钥对 - RS384成功")
        void generateKeyPair_RS384_Success() {
            boolean result = keyMinter.createKeyPair(Algorithm.RSA384);
            assertTrue(result);
        }

        @Test
        @DisplayName("生成RSA密钥对 - RS512成功")
        void generateKeyPair_RS512_Success() {
            boolean result = keyMinter.createKeyPair(Algorithm.RSA512);
            assertTrue(result);
        }

        @Test
        @DisplayName("生成RSA密钥对 - 无效算法抛出异常")
        void generateKeyPair_InvalidAlgorithm_ThrowsException() {
            assertThrows(IllegalArgumentException.class, () ->
                keyMinter.createKeyPair(Algorithm.HMAC256)
            );
        }

        @Test
        @DisplayName("生成所有RSA密钥对 - 成功")
        void generateAllKeyPairs_Success() {
            boolean result = keyMinter.generateAllKeyPairs();
            assertTrue(result);
            assertTrue(keyMinter.getKeyVersions().size() >= 3);
        }
    }

    @Nested
    @DisplayName("Token生成与验证测试")
    class TokenGenerationAndVerificationTests {

        @Test
        @DisplayName("生成并验证Token - RS256")
        void generateAndVerifyToken_RS256_Success() {
            keyMinter.createKeyPair(Algorithm.RSA256);
            keyMinter.switchTo(Algorithm.RSA256, null, null, true);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.RSA256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            JwtProperties jwtProps = createValidJwtProperties();
            String token = keyMinter.generateToken(jwtProps);

            assertNotNull(token);
            assertEquals(3, token.split("\\.").length);
            assertTrue(keyMinter.isValidToken(token));
        }

        @Test
        @DisplayName("生成Token - 带自定义claims")
        void generateToken_WithCustomClaims_Success() {
            keyMinter.createKeyPair(Algorithm.RSA256);
            keyMinter.switchTo(Algorithm.RSA256, null, null, true);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.RSA256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            JwtProperties jwtProps = createValidJwtProperties();
            Map<String, Object> customClaims = Map.of("role", "admin", "permissions", "read,write");

            String token = keyMinter.generateToken(jwtProps, customClaims, Map.class);

            assertNotNull(token);

            Map<String, Object> claims = keyMinter.decodeToFullMap(token);
            assertEquals("admin", claims.get("role"));
            assertEquals("read,write", claims.get("permissions"));
        }
    }
//
//        @Test
//        @DisplayName("验证Token - 使用公钥验证")
//        void verifyToken_WithPublicKey_Success() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            JwtProperties jwtProps = createValidJwtProperties();
//            String token = rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//
//            // 获取公钥
//            KeyPair keyPair = (KeyPair) rsaJwt.getCurrentKey();
//            PublicKey publicKey = keyPair.getPublic();
//
//            // 使用公钥验证（模拟外部验证）
//            assertDoesNotThrow(() -> {
//                java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
//                signature.initVerify(publicKey);
//            });
//
//            assertTrue(rsaJwt.verifyToken(token));
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("验证Token - 无效Token返回false")
//        void verifyToken_InvalidToken_ReturnsFalse() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            assertFalse(rsaJwt.verifyToken("invalid.token.here"));
//            assertFalse(rsaJwt.verifyToken(null));
//            assertFalse(rsaJwt.verifyToken(""));
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("验证Token - 使用错误密钥验证失败")
//        void verifyToken_WrongKey_Fails() throws Exception {
//            RsaJwt rsaJwt1 = new RsaJwt(properties, tempDir.resolve("key1"));
//            rsaJwt1.generateKeyPair(Algorithm.RSA256);
//
//            RsaJwt rsaJwt2 = new RsaJwt(properties, tempDir.resolve("key2"));
//            rsaJwt2.generateKeyPair(Algorithm.RSA256);
//
//            // 用key1生成token
//            JwtProperties jwtProps = createValidJwtProperties();
//            String token = rsaJwt1.generateToken(jwtProps, Algorithm.RSA256);
//
//            // 用key2验证应该失败
//            assertFalse(rsaJwt2.verifyToken(token));
//
//            rsaJwt1.close();
//            rsaJwt2.close();
//        }
//
//        @Test
//        @DisplayName("解码Token - 成功")
//        void decodePayload_Success() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            JwtProperties jwtProps = createValidJwtProperties();
//            String token = rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//
//            Claims claims = rsaJwt.decodePayload(token);
//
//            assertNotNull(claims);
//            assertEquals("test-subject", claims.getSubject());
//            assertEquals("test-issuer", claims.getIssuer());
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("解码Token - 空Token抛出异常")
//        void decodePayload_EmptyToken_ThrowsException() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            assertThrows(IllegalArgumentException.class, () ->
//                rsaJwt.decodePayload("")
//            );
//            assertThrows(IllegalArgumentException.class, () ->
//                rsaJwt.decodePayload(null)
//            );
//
//            rsaJwt.close();
//        }
//    }
//
//    // ==================== 密钥轮换测试 ====================
//
//    @Nested
//    @DisplayName("密钥轮换测试")
//    class KeyRotationTests {
//
//        @Test
//        @DisplayName("轮换RSA密钥 - 成功")
//        void rotateKey_Success() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            String oldKeyId = rsaJwt.getActiveKeyId();
//            KeyPair oldKeyPair = (KeyPair) rsaJwt.getCurrentKey();
//
//            // 轮换密钥
//            boolean result = rsaJwt.rotateKey(Algorithm.RSA256, "new-rsa-key-v1");
//
//            assertTrue(result);
//            String newKeyId = rsaJwt.getActiveKeyId();
//            KeyPair newKeyPair = (KeyPair) rsaJwt.getCurrentKey();
//
//            assertNotEquals(oldKeyId, newKeyId);
//            assertNotEquals(oldKeyPair.getPublic(), newKeyPair.getPublic());
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("使用旧密钥验证Token - 密钥轮换后")
//        void verifyWithOldKey_AfterRotation_Success() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            // 用旧密钥生成token
//            JwtProperties jwtProps = createValidJwtProperties();
//            String oldToken = rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//            String oldKeyId = rsaJwt.getActiveKeyId();
//
//            // 轮换密钥
//            rsaJwt.rotateKey(Algorithm.RSA256, "new-rsa-key-v1");
//
//            // 旧token应该仍能用旧密钥验证
//            assertTrue(rsaJwt.verifyWithKeyVersion(oldKeyId, oldToken));
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("获取密钥版本 - 成功")
//        void getKeyByVersion_Success() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//            String keyId = rsaJwt.getActiveKeyId();
//
//            KeyPair keyPair = (KeyPair) rsaJwt.getKeyByVersion(keyId);
//
//            assertNotNull(keyPair);
//            assertNotNull(keyPair.getPublic());
//            assertNotNull(keyPair.getPrivate());
//
//            rsaJwt.close();
//        }
//    }
//
//    // ==================== 并发测试 ====================
//
//    @Nested
//    @DisplayName("并发测试")
//    class ConcurrencyTests {
//
//        @Test
//        @DisplayName("并发生成Token - 线程安全")
//        void concurrentTokenGeneration_ThreadSafe() throws InterruptedException {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            int threadCount = 5;
//            int iterations = 20;
//            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
//            CountDownLatch latch = new CountDownLatch(threadCount);
//            AtomicInteger successCount = new AtomicInteger(0);
//
//            JwtProperties jwtProps = createValidJwtProperties();
//
//            for (int i = 0; i < threadCount; i++) {
//                executor.submit(() -> {
//                    try {
//                        for (int j = 0; j < iterations; j++) {
//                            String token = rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//                            if (token != null && rsaJwt.verifyToken(token)) {
//                                successCount.incrementAndGet();
//                            }
//                        }
//                    } finally {
//                        latch.countDown();
//                    }
//                });
//            }
//
//            assertTrue(latch.await(30, TimeUnit.SECONDS)); // RSA较慢，需要更多时间
//            executor.shutdown();
//            assertEquals(threadCount * iterations, successCount.get());
//
//            rsaJwt.close();
//        }
//    }
//
//    // ==================== 性能测试 ====================
//
//    @Nested
//    @DisplayName("性能测试")
//    class PerformanceTests {
//
//        @Test
//        @DisplayName("RSA256 Token生成性能")
//        void rsa256TokenGeneration_Performance() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            JwtProperties jwtProps = createValidJwtProperties();
//            int iterations = 100;
//
//            long startTime = System.currentTimeMillis();
//
//            for (int i = 0; i < iterations; i++) {
//                rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//            }
//
//            long duration = System.currentTimeMillis() - startTime;
//            double avgTime = (double) duration / iterations;
//
//            System.out.println("RSA256 Token生成平均耗时: " + avgTime + "ms");
//            assertTrue(avgTime < 100, "Token生成应该足够快 (< 100ms)");
//
//            rsaJwt.close();
//        }
//
//        @Test
//        @DisplayName("RSA256 Token验证性能")
//        void rsa256TokenVerification_Performance() {
//            RsaJwt rsaJwt = new RsaJwt(properties, tempDir);
//            rsaJwt.generateKeyPair(Algorithm.RSA256);
//
//            JwtProperties jwtProps = createValidJwtProperties();
//            String token = rsaJwt.generateToken(jwtProps, Algorithm.RSA256);
//
//            int iterations = 1000;
//            long startTime = System.currentTimeMillis();
//
//            for (int i = 0; i < iterations; i++) {
//                rsaJwt.verifyToken(token);
//            }
//
//            long duration = System.currentTimeMillis() - startTime;
//            double avgTime = (double) duration / iterations;
//
//            System.out.println("RSA256 Token验证平均耗时: " + avgTime + "ms");
//            assertTrue(avgTime < 10, "Token验证应该足够快 (< 10ms)");
//
//            rsaJwt.close();
//        }
//    }
//
//    // ==================== 辅助方法 ====================
//
//    private JwtProperties createValidJwtProperties() {
//        return JwtProperties.builder()
//                .subject("test-subject")
//                .issuer("test-issuer")
//                .expiration(Instant.now().plus(1, ChronoUnit.HOURS))
//                .build();
//    }
}
