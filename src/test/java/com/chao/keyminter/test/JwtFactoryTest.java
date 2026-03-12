package com.chao.keyminter.test;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.domain.model.Algorithm;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JwtFactory 单元测试
 * 测试工厂类的缓存和实例管理功能
 */
@DisplayName("JwtFactory 测试")
class JwtFactoryTest {

    @TempDir
    Path tempDir;

    private JwtFactory factory;
    private KeyMinterProperties properties;

    @BeforeEach
    void setUp() {
        factory = new JwtFactory();
        properties = new KeyMinterProperties();
        properties.setKeyDir(tempDir.toString());
        factory.setProperties(properties);
    }

    @AfterEach
    void tearDown() {
        if (factory != null) {
            factory.close();
        }
    }

    // ==================== 基本功能测试 ====================

    @Nested
    @DisplayName("基本功能测试")
    class BasicFunctionalityTests {

        @Test
        @DisplayName("获取默认HMAC256实例 - 成功")
        void get_DefaultHmac256_Success() {
            JwtAlgo algo = factory.get();
            
            assertNotNull(algo);
            assertNotNull(algo.getKeyInfo());
        }

        @Test
        @DisplayName("获取指定算法实例 - HMAC256")
        void get_SpecifiedAlgorithm_HMAC256() {
            JwtAlgo algo = factory.get(Algorithm.HMAC256);
            
            assertNotNull(algo);
            assertTrue(algo.getAlgorithmInfo().contains("HMAC"));
        }

        @Test
        @DisplayName("获取指定算法实例 - RSA256")
        void get_SpecifiedAlgorithm_RSA256() {
            JwtAlgo algo = factory.get(Algorithm.RSA256);
            
            assertNotNull(algo);
            assertTrue(algo.getAlgorithmInfo().contains("RSA"));
        }

        @Test
        @DisplayName("获取指定算法实例 - ES256")
        void get_SpecifiedAlgorithm_ES256() {
            JwtAlgo algo = factory.get(Algorithm.ES256);
            
            assertNotNull(algo);
            assertTrue(algo.getAlgorithmInfo().contains("ECDSA"));
        }

        @Test
        @DisplayName("获取指定算法实例 - Ed25519")
        void get_SpecifiedAlgorithm_Ed25519() {
            JwtAlgo algo = factory.get(Algorithm.Ed25519);
            
            assertNotNull(algo);
            assertTrue(algo.getAlgorithmInfo().contains("EdDSA"));
        }

        @Test
        @DisplayName("获取指定算法和目录 - 成功")
        void get_WithDirectory_Success() {
            JwtAlgo algo = factory.get(Algorithm.HMAC256, tempDir);
            
            assertNotNull(algo);
            assertEquals(tempDir.resolve("hmac-keys"), algo.getKeyPath());
        }

        @Test
        @DisplayName("获取指定算法和字符串目录 - 成功")
        void get_WithStringDirectory_Success() {
            JwtAlgo algo = factory.get(Algorithm.HMAC256, tempDir.toString());
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("获取实例 - 空算法抛出异常")
        void get_NullAlgorithm_ThrowsException() {
            assertThrows(NullPointerException.class, () -> 
                factory.get(null)
            );
        }
    }

    // ==================== 缓存测试 ====================

    @Nested
    @DisplayName("缓存测试")
    class CacheTests {

        @Test
        @DisplayName("缓存命中 - 相同参数返回相同实例")
        void cacheHit_SameParams_ReturnsSameInstance() {
            JwtAlgo algo1 = factory.get(Algorithm.HMAC256, tempDir);
            JwtAlgo algo2 = factory.get(Algorithm.HMAC256, tempDir);
            
            assertSame(algo1, algo2);
        }

        @Test
        @DisplayName("缓存未命中 - 不同参数返回不同实例")
        void cacheMiss_DifferentParams_ReturnsDifferentInstances() {
            JwtAlgo algo1 = factory.get(Algorithm.HMAC256, tempDir);
            JwtAlgo algo2 = factory.get(Algorithm.RSA256, tempDir);
            
            assertNotSame(algo1, algo2);
        }

        @Test
        @DisplayName("缓存大小 - 正确计数")
        void cacheSize_CorrectCount() {
            assertEquals(0, factory.getCacheSize());
            
            factory.get(Algorithm.HMAC256);
            assertEquals(1, factory.getCacheSize());
            
            factory.get(Algorithm.RSA256);
            assertEquals(2, factory.getCacheSize());
            
            // 再次获取相同实例，缓存大小不变
            factory.get(Algorithm.HMAC256);
            assertEquals(2, factory.getCacheSize());
        }

        @Test
        @DisplayName("清理缓存 - 成功")
        void clearCache_Success() {
            factory.get(Algorithm.HMAC256);
            factory.get(Algorithm.RSA256);
            assertEquals(2, factory.getCacheSize());
            
            factory.clearCache();
            
            assertEquals(0, factory.getCacheSize());
        }

        @Test
        @DisplayName("LRU缓存淘汰 - 超过最大实例数")
        void lruCacheEviction_MaxInstancesReached() {
            // 设置较小的最大实例数
            properties.setMaxAlgoInstance(2);
            factory.setProperties(properties);
            
            factory.get(Algorithm.HMAC256);
            factory.get(Algorithm.RSA256);
            assertEquals(2, factory.getCacheSize());
            
            // 添加第3个实例，应该淘汰最久未使用的
            factory.get(Algorithm.ES256);
            assertEquals(2, factory.getCacheSize());
        }
    }

    // ==================== 自动加载测试 ====================

    @Nested
    @DisplayName("自动加载测试")
    class AutoLoadTests {

        @Test
        @DisplayName("自动加载 - 默认参数")
        void autoLoad_DefaultParams_Success() {
            JwtAlgo algo = factory.autoLoad(Algorithm.HMAC256);
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("自动加载 - 强制重新加载")
        void autoLoad_ForceReload_Success() {
            JwtAlgo algo1 = factory.autoLoad(Algorithm.HMAC256);
            JwtAlgo algo2 = factory.autoLoad(Algorithm.HMAC256, true);
            
            // 强制重新加载可能返回不同实例
            assertNotNull(algo2);
        }

        @Test
        @DisplayName("自动加载 - 指定目录")
        void autoLoad_WithDirectory_Success() {
            JwtAlgo algo = factory.autoLoad(Algorithm.HMAC256, tempDir);
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("自动加载 - 指定字符串目录")
        void autoLoad_WithStringDirectory_Success() {
            JwtAlgo algo = factory.autoLoad(Algorithm.HMAC256, tempDir.toString());
            
            assertNotNull(algo);
        }

        @Test
        @DisplayName("自动加载 - 指定密钥ID")
        void autoLoad_WithKeyId_Success() {
            // 首先生成一个密钥
            JwtAlgo algo = factory.get(Algorithm.HMAC256, tempDir);
            algo.generateKeyPair(Algorithm.HMAC256);
            String keyId = algo.getActiveKeyId();
            
            // 使用密钥ID自动加载
            JwtAlgo loadedAlgo = factory.autoLoad(Algorithm.HMAC256, tempDir.toString(), keyId);
            
            assertNotNull(loadedAlgo);
        }

        @Test
        @DisplayName("自动加载 - 强制重新加载指定密钥ID")
        void autoLoad_WithKeyIdAndForce_Success() {
            JwtAlgo algo = factory.autoLoad(Algorithm.HMAC256, tempDir.toString(), "test-key", true);
            
            assertNotNull(algo);
        }
    }

    // ==================== 并发测试 ====================

    @Nested
    @DisplayName("并发测试")
    class ConcurrencyTests {

        @Test
        @DisplayName("并发获取实例 - 线程安全")
        void concurrentGet_ThreadSafe() throws InterruptedException {
            int threadCount = 10;
            int iterations = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            Algorithm algorithm = Algorithm.values()[index % Algorithm.values().length];
                            JwtAlgo algo = factory.get(algorithm);
                            if (algo != null) {
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
        @DisplayName("并发自动加载 - 线程安全")
        void concurrentAutoLoad_ThreadSafe() throws InterruptedException {
            int threadCount = 5;
            int iterations = 20;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            JwtAlgo algo = factory.autoLoad(Algorithm.HMAC256, tempDir);
                            if (algo != null) {
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
        @DisplayName("并发缓存操作 - 无数据竞争")
        void concurrentCacheOperations_NoRaceCondition() throws InterruptedException {
            int readerCount = 5;
            int writerCount = 2;
            int iterations = 50;
            
            ExecutorService readers = Executors.newFixedThreadPool(readerCount);
            ExecutorService writers = Executors.newFixedThreadPool(writerCount);
            CountDownLatch latch = new CountDownLatch(readerCount + writerCount);

            // 启动读者
            for (int i = 0; i < readerCount; i++) {
                readers.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            factory.getCacheSize();
                            factory.get(Algorithm.HMAC256);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            // 启动写者
            for (int i = 0; i < writerCount; i++) {
                final int index = i;
                writers.submit(() -> {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            factory.get(Algorithm.values()[index % 4]);
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(15, TimeUnit.SECONDS));
            readers.shutdown();
            writers.shutdown();
        }
    }

    // ==================== 关闭测试 ====================

    @Nested
    @DisplayName("关闭测试")
    class CloseTests {

        @Test
        @DisplayName("关闭工厂 - 清理所有资源")
        void close_CleansAllResources() {
            factory.get(Algorithm.HMAC256);
            factory.get(Algorithm.RSA256);
            assertEquals(2, factory.getCacheSize());
            
            factory.close();
            
            assertEquals(0, factory.getCacheSize());
        }

        @Test
        @DisplayName("多次关闭 - 不抛出异常")
        void close_MultipleTimes_NoException() {
            factory.get(Algorithm.HMAC256);
            
            assertDoesNotThrow(() -> {
                factory.close();
                factory.close();
                factory.close();
            });
        }
    }

    // ==================== 配置测试 ====================

    @Nested
    @DisplayName("配置测试")
    class ConfigurationTests {

        @Test
        @DisplayName("设置属性 - 成功")
        void setProperties_Success() {
            KeyMinterProperties newProps = new KeyMinterProperties();
            newProps.setMaxAlgoInstance(10);
            
            factory.setProperties(newProps);
            
            // 属性应该生效
            for (int i = 0; i < 15; i++) {
                factory.get(Algorithm.values()[i % Algorithm.values().length]);
            }
            // 由于设置了maxAlgoInstance=10，缓存大小应该不超过10
            assertTrue(factory.getCacheSize() <= 10);
        }

        @Test
        @DisplayName("设置属性 - 空属性使用默认值")
        void setProperties_NullProperties_UsesDefaults() {
            factory.setProperties(null);
            
            // 应该仍然可以正常工作
            JwtAlgo algo = factory.get(Algorithm.HMAC256);
            assertNotNull(algo);
        }
    }
}
