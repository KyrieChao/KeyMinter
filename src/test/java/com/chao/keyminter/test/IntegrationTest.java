package com.chao.keyminter.test;

import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.JwtStandardInfo;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 集成测试
 * 测试完整的JWT工作流程
 */
@DisplayName("集成测试")
class IntegrationTest {

    @TempDir
    Path tempDir;

    private JwtFactory factory;
    private KeyMinter keyMinter;

    @BeforeEach
    void setUp() {
        KeyMinterProperties properties = new KeyMinterProperties();
        properties.setKeyDir(tempDir.toString());
        properties.setEnableRotation(true);

        factory = new JwtFactory();
        factory.setProperties(properties);
        keyMinter = new KeyMinter(factory);
    }

    @AfterEach
    void tearDown() {
        if (keyMinter != null) {
            keyMinter.close();
        }
        if (factory != null) {
            factory.close();
        }
    }

    // ==================== 端到端测试 ====================

    @Nested
    @DisplayName("端到端测试")
    class EndToEndTests {

        @Test
        @DisplayName("完整HMAC工作流程 - HS256")
        void completeHmacWorkflow_HS256() {
            // 1. 生成密钥 (先生成密钥，否则switchTo会失败)
            assertTrue(keyMinter.createHmacKey(Algorithm.HMAC256, 64));
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            // 2. 切换到HMAC256 (虽然默认是HMAC256，但为了测试切换功能)
            assertTrue(keyMinter.switchTo(Algorithm.HMAC256, null, null, true));

            // 3. 生成Token
            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);
            assertNotNull(token);

            // 4. 验证Token
            assertTrue(keyMinter.isValidToken(token));

            // 5. 解码Token
            JwtStandardInfo info = keyMinter.getStandardInfo(token);
            assertNotNull(info);
            assertEquals("test-subject", info.getSubject());

            // 6. 检查密钥版本
            List<String> versions = keyMinter.getKeyVersions();
            assertFalse(versions.isEmpty());
        }

        @Test
        @DisplayName("完整RSA工作流程 - RS256")
        void completeRsaWorkflow_RS256() {
            // 1. 生成RSA密钥
            assertTrue(keyMinter.createKeyPair(Algorithm.RSA256));
            List<String> keys = keyMinter.getKeyVersions(Algorithm.RSA256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            // 2. 切换到RSA256
            assertTrue(keyMinter.switchTo(Algorithm.RSA256, null, null, true));

            // 3. 生成Token
            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);
            assertNotNull(token);

            // 4. 验证Token
            assertTrue(keyMinter.isValidToken(token));

            // 5. 获取算法信息
            String algoInfo = keyMinter.getAlgorithmInfo();
            assertTrue(algoInfo.contains("RSA"));
        }

        @Test
        @DisplayName("完整ECDSA工作流程 - ES256")
        void completeEcdsaWorkflow_ES256() {
            // 1. 生成ECDSA密钥
            assertTrue(keyMinter.createKeyPair(Algorithm.ES256));

            // 2. 切换到ES256
            assertTrue(keyMinter.switchTo(Algorithm.ES256, null, null, true));

            // 3. 生成Token
            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);
            assertNotNull(token);

            // 4. 验证Token
            assertTrue(keyMinter.isValidToken(token));

            // 5. 获取曲线信息
            String curveInfo = keyMinter.getECDCurveInfo();
            assertNotNull(curveInfo);
        }

        @Test
        @DisplayName("完整EdDSA工作流程 - Ed25519")
        void completeEddsaWorkflow_Ed25519() {
            // 1. 生成EdDSA密钥
            assertTrue(keyMinter.createKeyPair(Algorithm.Ed25519));

            // 2. 切换到Ed25519
            assertTrue(keyMinter.switchTo(Algorithm.Ed25519, null, null, true));

            // 3. 生成Token
            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);
            assertNotNull(token);

            // 4. 验证Token
            assertTrue(keyMinter.isValidToken(token));
        }
    }

    // ==================== 算法切换测试 ====================

    @Nested
    @DisplayName("算法切换测试")
    class AlgorithmSwitchTests {

        @Test
        @DisplayName("切换多个算法 - 成功")
        void switchMultipleAlgorithms_Success() {
            // HMAC
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);
            String hmacToken = keyMinter.generateToken(createJwtProperties());
            assertTrue(keyMinter.isValidToken(hmacToken));

            // RSA
            keyMinter.createKeyPair(Algorithm.RSA256);
            keyMinter.switchTo(Algorithm.RSA256, tempDir, true);
            String rsaToken = keyMinter.generateToken(createJwtProperties());
            assertTrue(keyMinter.isValidToken(rsaToken));

            // 切换回HMAC
            keyMinter.switchTo(Algorithm.HMAC256, null, null, true);
            assertTrue(keyMinter.isValidToken(hmacToken)); // 旧token仍然有效
        }

        @Test
        @DisplayName("使用工厂缓存 - 相同算法返回缓存实例")
        void factoryCache_SameAlgorithm_ReturnsCachedInstance() {
            JwtAlgo algo1 = factory.get(Algorithm.HMAC256, tempDir);
            JwtAlgo algo2 = factory.get(Algorithm.HMAC256, tempDir);

            assertSame(algo1, algo2);
        }
    }

    // ==================== 密钥轮换测试 ====================

    @Nested
    @DisplayName("密钥轮换测试")
    class KeyRotationTests {

        @Test
        @DisplayName("HMAC密钥轮换 - 旧Token仍有效")
        void hmacKeyRotation_OldTokenStillValid() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            // 生成旧Token
            String oldToken = keyMinter.generateToken(createJwtProperties());
            String oldKeyId = keyMinter.getActiveKeyId();

            // 轮换密钥
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);
            String newKeyId = keyMinter.getActiveKeyId();

            // 旧Token应该仍能用旧密钥验证
            assertNotEquals(oldKeyId, newKeyId);
            assertTrue(keyMinter.verify(Algorithm.HMAC256, oldToken));
        }

        @Test
        @DisplayName("RSA密钥轮换 - 旧Token仍有效")
        void rsaKeyRotation_OldTokenStillValid() {
            keyMinter.createKeyPair(Algorithm.RSA256);
            keyMinter.switchTo(Algorithm.RSA256, null, null, true);

            // 生成旧Token
            String oldToken = keyMinter.generateToken(createJwtProperties());

            // 轮换密钥
            keyMinter.createKeyPair(Algorithm.RSA256);

            // 旧Token应该仍有效
            assertTrue(keyMinter.verify(Algorithm.RSA256, oldToken));
        }

        @Test
        @DisplayName("生成所有算法密钥 - 成功")
        void generateAllKeys_Success() {
            assertTrue(keyMinter.generateAllKeyPairs());

            // 验证所有算法都有密钥
            assertTrue(keyMinter.keyPairExists());
        }
    }

    // ==================== 自定义Claims测试 ====================

    @Nested
    @DisplayName("自定义Claims测试")
    class CustomClaimsTests {

        @Test
        @DisplayName("生成带自定义Claims的Token - 成功")
        void generateToken_WithCustomClaims_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            JwtProperties props = createJwtProperties();
            Map<String, Object> customClaims = Map.of(
                    "userId", "12345",
                    "role", "admin",
                    "permissions", List.of("read", "write", "delete")
            );

            String token = keyMinter.generateToken(props, customClaims, Map.class);
            assertNotNull(token);

            // 解码验证
            Map<String, Object> decoded = keyMinter.decodeToObject(token, Map.class);
            assertEquals("12345", decoded.get("userId"));
            assertEquals("admin", decoded.get("role"));
        }

        @Test
        @DisplayName("安全获取自定义Claims - 成功")
        void getCustomClaimsSafe_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);

            // 安全获取（不抛出异常）
            Map<String, Object> claims = keyMinter.getCustomClaimsSafe(token, Map.class);
            // 可能返回null或空map，但不抛出异常
        }
    }

    // ==================== 高并发测试 ====================

    @Nested
    @DisplayName("高并发测试")
    class HighConcurrencyTests {

        @Test
        @DisplayName("高并发生成Token - 100线程")
        void highConcurrentTokenGeneration_100Threads() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            int threadCount = 100;
            int iterations = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);
            List<String> tokens = Collections.synchronizedList(new ArrayList<>());

            JwtProperties props = createJwtProperties();

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            String token = keyMinter.generateToken(props);
                            if (token != null) {
                                tokens.add(token);
                                successCount.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(30, TimeUnit.SECONDS));
            executor.shutdown();

            assertEquals(threadCount * iterations, successCount.get());
            assertEquals(threadCount * iterations, tokens.size());

            // 验证所有token都有效
            for (String token : tokens) {
                assertTrue(keyMinter.isValidToken(token));
            }
        }

        @Test
        @DisplayName("高并发验证Token - 200线程")
        void highConcurrentTokenVerification_200Threads() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            // 预生成token
            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);

            int threadCount = 200;
            int iterations = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            if (keyMinter.isValidToken(token)) {
                                successCount.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(15, TimeUnit.SECONDS));
            executor.shutdown();
            assertEquals(threadCount * iterations, successCount.get());
        }

        @Test
        @DisplayName("混合读写操作 - 并发安全")
        void mixedReadWrite_Operations_ThreadSafe() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            int readerCount = 50;
            int writerCount = 10;
            int iterations = 20;

            ExecutorService readers = Executors.newFixedThreadPool(readerCount);
            ExecutorService writers = Executors.newFixedThreadPool(writerCount);
            CountDownLatch latch = new CountDownLatch(readerCount + writerCount);
            AtomicInteger successCount = new AtomicInteger(0);

            JwtProperties props = createJwtProperties();

            // 启动读者
            for (int i = 0; i < readerCount; i++) {
                readers.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            String token = keyMinter.generateToken(props);
                            if (keyMinter.isValidToken(token)) {
                                successCount.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            // 启动写者（轮换密钥）
            for (int i = 0; i < writerCount; i++) {
                writers.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(30, TimeUnit.SECONDS));
            readers.shutdown();
            writers.shutdown();

            // 所有读操作都应该成功
            assertEquals(readerCount * iterations, successCount.get());
        }
    }

    // ==================== 性能测试 ====================

    @Nested
    @DisplayName("性能测试")
    class PerformanceTests {

        @Test
        @DisplayName("HMAC Token生成性能 - 1000次")
        void hmacTokenGenerationPerformance_1000Iterations() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            JwtProperties props = createJwtProperties();
            int iterations = 1000;

            long startTime = System.currentTimeMillis();

            for (int i = 0; i < iterations; i++) {
                keyMinter.generateToken(props);
            }

            long duration = System.currentTimeMillis() - startTime;
            double avgTime = (double) duration / iterations;

            System.out.println("HMAC Token生成 " + iterations + " 次，总耗时: " + duration + "ms");
            System.out.println("平均每次: " + avgTime + "ms");

            assertTrue(avgTime < 5, "HMAC Token生成应该足够快 (< 5ms)");
        }

        @Test
        @DisplayName("HMAC Token验证性能 - 10000次")
        void hmacTokenVerificationPerformance_10000Iterations() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            JwtProperties props = createJwtProperties();
            String token = keyMinter.generateToken(props);

            int iterations = 10000;
            long startTime = System.currentTimeMillis();

            for (int i = 0; i < iterations; i++) {
                keyMinter.isValidToken(token);
            }

            long duration = System.currentTimeMillis() - startTime;
            double avgTime = (double) duration / iterations;

            System.out.println("HMAC Token验证 " + iterations + " 次，总耗时: " + duration + "ms");
            System.out.println("平均每次: " + avgTime + "ms");

            assertTrue(avgTime < 1, "HMAC Token验证应该足够快 (< 1ms)");
        }

        @Test
        @DisplayName("RSA Token生成性能 - 100次")
        void rsaTokenGenerationPerformance_100Iterations() {
            keyMinter.createKeyPair(Algorithm.RSA256);
            keyMinter.switchTo(Algorithm.RSA256, null, null, true);

            JwtProperties props = createJwtProperties();
            int iterations = 100;

            long startTime = System.currentTimeMillis();

            for (int i = 0; i < iterations; i++) {
                keyMinter.generateToken(props);
            }

            long duration = System.currentTimeMillis() - startTime;
            double avgTime = (double) duration / iterations;

            System.out.println("RSA Token生成 " + iterations + " 次，总耗时: " + duration + "ms");
            System.out.println("平均每次: " + avgTime + "ms");

            assertTrue(avgTime < 50, "RSA Token生成应该足够快 (< 50ms)");
        }
    }

    // ==================== 错误处理测试 ====================

    @Nested
    @DisplayName("错误处理测试")
    class ErrorHandlingTests {

        @Test
        @DisplayName("验证无效Token - 返回false")
        void verifyInvalidToken_ReturnsFalse() {
            assertFalse(keyMinter.isValidToken("invalid.token.here"));
            assertFalse(keyMinter.isValidToken(null));
            assertFalse(keyMinter.isValidToken(""));
        }

        @Test
        @DisplayName("解码无效Token - 抛出异常或返回null")
        void decodeInvalidToken_HandlesGracefully() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            // 安全方法应该返回null
            assertNull(keyMinter.getStandardInfo("invalid.token"));
            assertNull(keyMinter.decodeExpiration("invalid.token"));
        }

        @Test
        @DisplayName("无密钥生成Token - 抛出异常")
        void generateToken_NoKey_ThrowsException() {
            keyMinter.switchTo(Algorithm.HMAC256);
            // 不生成密钥

            assertThrows(Exception.class, () ->
                    keyMinter.generateToken(createJwtProperties())
            );
        }

        @Test
        @DisplayName("过期Token生成 - 抛出异常")
        void verifyExpiredToken_Fails() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            keyMinter.autoLoad(Algorithm.HMAC256, true);

            // 创建已过期的JWT属性
            JwtProperties expiredProps = JwtProperties.builder()
                    .subject("test-subject")
                    .issuer("test-issuer")
                    .expiration(Instant.now().minusSeconds(1))
                    .build();

            // 生成过期token应该失败
            assertThrows(IllegalArgumentException.class, () -> 
                keyMinter.generateToken(expiredProps)
            );
        }
    }

    // ==================== 辅助方法 ====================

    private JwtProperties createJwtProperties() {
        return JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
    }
}
