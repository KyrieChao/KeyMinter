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
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyMinter 单元测试
 * 测试主入口类的完整功能
 */
@DisplayName("KeyMinter 测试")
class KeyMinterTest {

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

    // ==================== 算法切换测试 ====================

    @Nested
    @DisplayName("算法切换测试")
    class AlgorithmSwitchTests {

        @Test
        @DisplayName("切换到HMAC256 - 成功")
        void switchTo_HMAC256_Success() {
            boolean result = keyMinter.switchTo(Algorithm.HMAC256);
            
            assertTrue(result);
            assertNotNull(keyMinter.getAlgorithmInfo());
        }

        @Test
        @DisplayName("切换到RSA256 - 成功")
        void switchTo_RSA256_Success() {
            // 先生成RSA密钥
            JwtAlgo rsaAlgo = factory.get(Algorithm.RSA256, tempDir);
            rsaAlgo.generateKeyPair(Algorithm.RSA256);
            
            boolean result = keyMinter.switchTo(Algorithm.RSA256, tempDir, true);
            
            assertTrue(result);
            assertTrue(keyMinter.getAlgorithmInfo().contains("RSA"));
            
            rsaAlgo.close();
        }

        @Test
        @DisplayName("切换到无效算法 - 失败")
        void switchTo_NoKeyPairExists_Fails() {
            // 尝试切换到没有密钥的RSA算法
            boolean result = keyMinter.switchTo(Algorithm.RSA256, tempDir.resolve("nonexistent"), true);
            
            assertFalse(result);
        }

        @Test
        @DisplayName("切换算法 - 空算法抛出异常")
        void switchTo_NullAlgorithm_ThrowsException() {
            assertThrows(NullPointerException.class, () -> 
                keyMinter.switchTo(null)
            );
        }

        @Test
        @DisplayName("切换算法 - 使用路径")
        void switchTo_WithPath_Success() {
            // 先生成密钥
            JwtAlgo algo = factory.get(Algorithm.HMAC256, tempDir);
            algo.generateKeyPair(Algorithm.HMAC256);
            
            boolean result = keyMinter.switchTo(Algorithm.HMAC256, tempDir, true);
            
            assertTrue(result);
        }
    }

    // ==================== Token生成测试 ====================

    @Nested
    @DisplayName("Token生成测试")
    class TokenGenerationTests {

        @Test
        @DisplayName("生成Token - 使用默认算法")
        void generateToken_DefaultAlgorithm_Success() {
            // 先生成密钥
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            assertNotNull(token);
            assertTrue(token.split("\\.").length == 3);
        }

        @Test
        @DisplayName("生成Token - 指定算法")
        void generateToken_SpecifiedAlgorithm_Success() {
            keyMinter.switchTo(Algorithm.HMAC512);
            keyMinter.createHmacKey(Algorithm.HMAC512, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC512);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props); // 使用当前切换的算法
            
            assertNotNull(token);
        }

        @Test
        @DisplayName("生成Token - 带自定义claims")
        void generateToken_WithCustomClaims_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            TestPayload payload = new TestPayload("admin", 12345);
            
            String token = keyMinter.generateToken(props, payload, TestPayload.class);
            
            assertNotNull(token);
            
            // 验证自定义claims
            TestPayload decoded = keyMinter.getCustomClaims(token, TestPayload.class);
            assertEquals("admin", decoded.getRole());
            assertEquals(12345, decoded.getUserId());
        }

        @Test
        @DisplayName("生成Token - 空属性抛出异常")
        void generateToken_NullProperties_ThrowsException() {
            assertThrows(NullPointerException.class, () -> 
                keyMinter.generateToken(null)
            );
        }
    }

    // ==================== Token验证测试 ====================

    @Nested
    @DisplayName("Token验证测试")
    class TokenVerificationTests {

        @Test
        @DisplayName("验证有效Token - 成功")
        void isValidToken_ValidToken_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            assertTrue(keyMinter.isValidToken(token));
        }

        @Test
        @DisplayName("验证无效Token - 失败")
        void isValidToken_InvalidToken_Fails() {
            assertFalse(keyMinter.isValidToken("invalid.token"));
            assertFalse(keyMinter.isValidToken(null));
            assertFalse(keyMinter.isValidToken(""));
        }

        @Test
        @DisplayName("仅使用当前算法验证 - 严格模式")
        void isValidWithCurrent_StrictMode() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            assertTrue(keyMinter.isValidWithCurrent(token));
        }

        @Test
        @DisplayName("使用指定算法验证 - 成功")
        void verify_WithSpecifiedAlgorithm_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            assertTrue(keyMinter.verify(Algorithm.HMAC256, token));
        }
    }

    // ==================== Token解码测试 ====================

    @Nested
    @DisplayName("Token解码测试")
    class TokenDecodingTests {

        @Test
        @DisplayName("获取标准信息 - 成功")
        void getStandardInfo_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            JwtStandardInfo info = keyMinter.getStandardInfo(token);
            
            assertNotNull(info);
            assertEquals("test-subject", info.getSubject());
            assertEquals("test-issuer", info.getIssuer());
        }

        @Test
        @DisplayName("解码为对象 - 成功")
        void decodeToObject_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            Map<String, Object> claims = Map.of("role", "admin", "userId", 12345);
            String token = keyMinter.generateToken(props, claims, Map.class);
            Map<String, Object> decoded = keyMinter.decodeToObject(token, Map.class);

            assertNotNull(decoded);
        }

        @Test
        @DisplayName("解码过期时间 - 成功")
        void decodeExpiration_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            Instant expiration = Instant.now().plus(1, ChronoUnit.HOURS);
            JwtProperties props = JwtProperties.builder()
                    .subject("test-subject")
                    .issuer("test-issuer")
                    .expiration(expiration)
                    .build();
            String token = keyMinter.generateToken(props);
            
            java.util.Date decodedExp = keyMinter.decodeExpiration(token);
            
            assertNotNull(decodedExp);
            // 允许1秒的误差
            assertTrue(Math.abs(decodedExp.getTime() - expiration.toEpochMilli()) < 1000);
        }

        @Test
        @DisplayName("安全获取自定义claims - 成功")
        void getCustomClaimsSafe_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            // 安全获取，不抛出异常
            TestPayload payload = keyMinter.getCustomClaimsSafe(token, TestPayload.class);
            // 因为没有设置自定义claims，可能返回null或空对象
        }

        @Test
        @DisplayName("检查Token是否可解码 - 成功")
        void isTokenDecodable_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);
            
            assertTrue(keyMinter.isTokenDecodable(token));
            assertFalse(keyMinter.isTokenDecodable("invalid"));
        }
    }

    // ==================== 密钥管理测试 ====================

    @Nested
    @DisplayName("密钥管理测试")
    class KeyManagementTests {

        @Test
        @DisplayName("生成HMAC密钥 - 成功")
        void createHmacKey_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            
            boolean result = keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            
            assertTrue(result);
            assertTrue(keyMinter.keyPairExists());
        }

        @Test
        @DisplayName("生成密钥对 - RSA")
        void createKeyPair_RSA_Success() {
            boolean result = keyMinter.createKeyPair(Algorithm.RSA256);
            
            assertTrue(result);
        }

        @Test
        @DisplayName("生成所有密钥对 - 成功")
        void generateAllKeyPairs_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            
            boolean result = keyMinter.generateAllKeyPairs();
            
            assertTrue(result);
        }

        @Test
        @DisplayName("获取密钥版本列表 - 成功")
        void getKeyVersions_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            
            var versions = keyMinter.getKeyVersions();
            
            assertNotNull(versions);
            assertFalse(versions.isEmpty());
        }

        @Test
        @DisplayName("获取活跃密钥ID - 成功")
        void getActiveKeyId_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));
            
            String keyId = keyMinter.getActiveKeyId();
            
            assertNotNull(keyId);
        }

        @Test
        @DisplayName("列出所有密钥 - 成功")
        void listAllKeys_Success() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            
            var keys = keyMinter.listAllKeys();
            
            assertNotNull(keys);
        }
    }

    // ==================== 自动加载测试 ====================

    @Nested
    @DisplayName("自动加载测试")
    class AutoLoadTests {

        @Test
        @DisplayName("自动加载 - 默认参数")
        void autoLoad_DefaultParams_Success() {
            JwtAlgo algo = keyMinter.autoLoad(Algorithm.HMAC256);
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("自动加载 - 指定目录")
        void autoLoad_WithDirectory_Success() {
            JwtAlgo algo = keyMinter.autoLoad(Algorithm.HMAC256, tempDir);
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("自动加载 - 指定密钥ID")
        void autoLoad_WithKeyId_Success() {
            // 先生成密钥
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) {
                keyMinter.setActiveKey(keys.get(0));
            }
            String keyId = keyMinter.getActiveKeyId();
            
            if (keyId != null) {
                JwtAlgo algo = keyMinter.autoLoad(Algorithm.HMAC256, tempDir.toString(), keyId);
                assertNotNull(algo);
            }
        }
    }

    // ==================== 指标测试 ====================

    @Nested
    @DisplayName("指标测试")
    class MetricsTests {

        @Test
        @DisplayName("获取指标 - 成功")
        void getMetrics_Success() {
            Map<String, Long> metrics = keyMinter.getMetrics();
            
            assertNotNull(metrics);
            assertTrue(metrics.containsKey("gracefulUsage"));
            assertTrue(metrics.containsKey("blacklistHit"));
        }

        @Test
        @DisplayName("重置指标 - 成功")
        void resetMetrics_Success() {
            keyMinter.resetMetrics();
            
            Map<String, Long> metrics = keyMinter.getMetrics();
            assertEquals(0L, metrics.get("gracefulUsage"));
            assertEquals(0L, metrics.get("blacklistHit"));
        }
    }

    // ==================== 并发测试 ====================

    @Nested
    @DisplayName("并发测试")
    class ConcurrencyTests {

        @Test
        @DisplayName("并发生成Token - 线程安全")
        void concurrentTokenGeneration_ThreadSafe() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            int threadCount = 5;
            int iterations = 20;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            JwtProperties props = createValidJwtProperties();

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            String token = keyMinter.generateToken(props);
                            if (token != null && keyMinter.isValidToken(token)) {
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
        @DisplayName("并发验证Token - 线程安全")
        void concurrentTokenVerification_ThreadSafe() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            List<String> keys = keyMinter.getKeyVersions(Algorithm.HMAC256);
            if (!keys.isEmpty()) keyMinter.setActiveKey(keys.get(0));

            JwtProperties props = createValidJwtProperties();
            String token = keyMinter.generateToken(props);

            int threadCount = 10;
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

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            executor.shutdown();
            assertEquals(threadCount * iterations, successCount.get());
        }

        @Test
        @DisplayName("并发切换算法 - 线程安全")
        void concurrentAlgorithmSwitch_ThreadSafe() throws InterruptedException {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);

            int threadCount = 5;
            int iterations = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            // 切换算法（使用同步方法）
                            keyMinter.switchTo(Algorithm.HMAC256);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            executor.shutdown();
        }
    }

    // ==================== 关闭测试 ====================

    @Nested
    @DisplayName("关闭测试")
    class CloseTests {

        @Test
        @DisplayName("关闭KeyMinter - 清理资源")
        void close_CleansResources() {
            keyMinter.switchTo(Algorithm.HMAC256);
            keyMinter.createHmacKey(Algorithm.HMAC256, 64);
            
            assertDoesNotThrow(() -> keyMinter.close());
        }

        @Test
        @DisplayName("多次关闭 - 不抛出异常")
        void close_MultipleTimes_NoException() {
            assertDoesNotThrow(() -> {
                keyMinter.close();
                keyMinter.close();
            });
        }
    }

    // ==================== 辅助方法 ====================

    private JwtProperties createValidJwtProperties() {
        return JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
    }

    /**
     * 测试用的payload类
     */
    static class TestPayload {
        private String role;
        private int userId;
        
        public TestPayload() {}
        
        public TestPayload(String role, int userId) {
            this.role = role;
            this.userId = userId;
        }
        
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        public int getUserId() { return userId; }
        public void setUserId(int userId) { this.userId = userId; }
    }
}
