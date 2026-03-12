package com.chao.keyminter.test;

import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.adapter.in.spring.KeyMinterAutoConfiguration;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.JwtStandardInfo;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HmacJwt 单元测试
 * 测试HMAC算法的完整功能
 */
@Slf4j
@SpringBootTest(classes = KeyMinterAutoConfiguration.class)
@TestPropertySource(properties = "key-minter.key-dir=${user.home}/.keyminter-test-env")
public class HmacJwtTest {

    @Autowired
    private KeyMinter key;

    @Test
    @DisplayName("HMAC: Lifecycle and Basic Operations")
    void testHmacLifecycle() {
        // 1. Create Key
        boolean b = key.createHmacKey(Algorithm.HMAC256, 64);
        assertTrue(b);
        List<String> keys = key.getKeyVersions(Algorithm.HMAC256);
        if (!keys.isEmpty()) key.setActiveKey(keys.get(0));
        
        // 2. Switch
        boolean condition = key.switchTo(Algorithm.HMAC256, null, null, true);
        assertTrue(condition);
        // 3. Generate Token
        JwtProperties props = JwtProperties.builder()
                .subject("test-user")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();
        String token = key.generateToken(props);
        assertNotNull(token);
        // 4. Verify
        assertTrue(key.isValidToken(token));
        // 5. Decode
        JwtStandardInfo info = key.getStandardInfo(token);
        assertEquals("test-user", info.getSubject());
        assertEquals("test-issuer", info.getIssuer());
        // 6. Decode Map
        Map<String, Object> map = key.decodeToFullMap(token);
        assertEquals("test-user", map.get("sub"));
        // 7. Check Decodable
        assertTrue(key.isTokenDecodable(token));
    }

    @Test
    @DisplayName("生成HMAC密钥 - HS256成功")
    void generateHmacKey_HS256_Success() {
//        boolean result = key.createHmacKey(Algorithm.HMAC256, 64);

        boolean b = key.switchTo(Algorithm.HMAC256,"HMAC256-v20260312-094843-e4002cb1");
//        assertTrue(result);
        assertTrue(b);
//        assertTrue(key.keyPairExists());
//        assertNotNull(key.getActiveKeyId());
//        log.info("exit:{},active:{} 1", key.keyPairExists(), key.getActiveKeyId());
        key.close();
    }

    @Test
    @DisplayName("生成HMAC密钥 - HS384成功")
    void generateHmacKey_HS384_Success() {
//        key.clearCache();
//        boolean result = key.createHmacKey(Algorithm.HMAC384, 64);
//        boolean b = key.switchTo(Algorithm.HMAC384);
//        boolean result = key.createHmacKey(Algorithm.HMAC384, 64);
//        assertTrue(result);
//        assertTrue(b);
//        assertTrue(key.keyPairExists());
//        assertNotNull(key.getActiveKeyId());

        key.close();
    }

    @Test
    @DisplayName("生成HMAC密钥 - HS384成功")
    void Test_HS() {
        boolean result = key.createHmacKey(Algorithm.HMAC512, 64);
//        boolean b = key.switchTo(Algorithm.HMAC384);
        log.info("exit:{},active:{} 2", key.keyPairExists(), key.getActiveKeyId());
        key.close();
    }

    @Test
    @DisplayName("生成HMAC密钥 - 默认长度")
    void generateHmacKey_DefaultLength_Success() {
        boolean result = key.createHmacKey(Algorithm.HMAC512, null);
        boolean b = key.switchTo(Algorithm.HMAC512);
        assertTrue(result);
        assertTrue(b);
        assertTrue(key.keyPairExists());
        assertNotNull(key.getActiveKeyId());
        System.out.println("exit:" + key.keyPairExists() + ",active:" + key.getActiveKeyId() + " 2.5");
        key.close();
    }

    @Test
    @DisplayName("生成HMAC密钥 - 未启用轮换抛出异常")
    void generateHmacKey_RotationDisabled_ThrowsException() {
//            properties.setEnableRotation(false);
        assertFalse(key.createHmacKey(Algorithm.HMAC256, 64));
        key.close();
    }

    @Test
    @DisplayName("生成HMAC密钥 - 无效算法抛出异常")
    void generateHmacKey_InvalidAlgorithm_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> key.createHmacKey(Algorithm.RSA256, 64));
        key.close();
    }

    @Test
    @DisplayName("生成所有HMAC密钥 - 成功")
    void generateAllKeyPairs_Success() {
        boolean result = key.generateAllKeyPairs();
        assertTrue(result);
        assertTrue(key.getKeyVersions().size() >= 3); // HS256, HS384, HS512
        key.close();
    }

    @Test
    @DisplayName("生成并验证Token - HS256成功")
    void generateAndVerifyToken_HS256_Success() {
        key.createHmacKey(Algorithm.HMAC256, 32);
        List<String> keys = key.getKeyVersions(Algorithm.HMAC256);
        if (!keys.isEmpty()) key.setActiveKey(keys.get(0));
        key.switchTo(Algorithm.HMAC256, null, null, true);

        JwtProperties jwtProps = createValidJwtProperties();
        String token = key.generateToken(jwtProps);
        assertNotNull(token);
        assertTrue(key.isValidToken(token));
        key.close();
    }

    @Test
    @DisplayName("生成Token - 带自定义claims")
    void generateToken_WithCustomClaims_Success() {
        key.createHmacKey(Algorithm.HMAC256, 32);
        List<String> keys = key.getKeyVersions(Algorithm.HMAC256);
        if (!keys.isEmpty()) key.setActiveKey(keys.get(0));
        key.switchTo(Algorithm.HMAC256, null, null, true);

        JwtProperties jwtProps = createValidJwtProperties();
        Map<String, Object> customClaims = Map.of("role", "admin", "userId", "12345");
        String token = key.generateToken(jwtProps, customClaims, Map.class);
        assertNotNull(token);

        // 解码验证claims
        Map<String, Object> claims = key.decodeToFullMap(token);
        assertEquals("admin", claims.get("role"));
        assertEquals("12345", claims.get("userId"));
        key.close();
    }

    @Test
    @DisplayName("验证Token - 无效Token返回false")
    void verifyToken_InvalidToken_ReturnsFalse() {
        assertFalse(key.isValidToken("invalid.token.here"));
        assertFalse(key.isValidToken(null));
        assertFalse(key.isValidToken(""));
    }

    @Test
    @DisplayName("验证Token - 篡改Token失败")
    void verifyToken_TamperedToken_Fails() {
        boolean b = key.switchTo(Algorithm.HMAC256);
        assertTrue(b);
        JwtProperties jwtProps = createValidJwtProperties();
        String token = key.generateToken(jwtProps);
        // 篡改token
        String tamperedToken = token.substring(0, token.length() - 5) + "XXXXX";
        assertFalse(key.isValidWithCurrent(tamperedToken));
        key.close();
    }

    @Test
    @DisplayName("验证Token - 过期Token失败")
    void verifyToken_ExpiredToken_Fails() throws InterruptedException {
        // 创建已过期的JWT属性
        JwtProperties expiredProps = JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(Duration.ofSeconds(15)))
                .build();
        // 生成过期token
        String expiredToken = key.generateToken(expiredProps);
        Thread.sleep(15000);
        // 验证应该失败（因为token已过期）
        assertFalse(key.isValidToken(expiredToken));
        key.close();
    }

    @Test
    @DisplayName("使用旧密钥验证Token - 密钥轮换后")
    void verifyWithOldKey_AfterRotation_Success() {
        // 用旧密钥生成token
        JwtProperties jwtProps = createValidJwtProperties();
        boolean b = key.switchTo(Algorithm.HMAC256, "HMAC256-v20260131-112044-a4e72aed");
        assertTrue(b);
        String oldToken = key.generateToken(jwtProps);
        String oldKeyId = key.getActiveKeyId();
        // 轮换密钥
        boolean b2 = key.switchTo(Algorithm.HMAC512, "HMAC512-v20260131-112045-c8f6ea2d");
        String newId = key.getActiveKeyId();
        assertTrue(b2);
        // 旧token应该仍能用旧密钥验证
        System.out.println("old:" + oldKeyId + ",new:" + newId);
        assertTrue(key.isValidToken(oldToken));
        key.close();
    }

    @Test
    @DisplayName("轮换HMAC密钥 - 成功")
    void rotateHmacKey_Success() {
        String oldKeyId = key.getActiveKeyId();
        boolean result = key.switchTo(Algorithm.HMAC384, "HMAC384-v20260131-112044-2d2e14a4");
        assertTrue(result);
        String newKeyId = key.getActiveKeyId();
        assertNotEquals(oldKeyId, newKeyId);
        assertTrue(key.getKeyVersions().size() >= 2);
        key.close();
    }

    @Test
    @DisplayName("设置活跃密钥 - 成功")
    void setActiveKey_Success() {
        String keyId1 = key.getActiveKeyId();
        System.out.println("keyId1: " + keyId1);
        boolean b = key.switchTo(Algorithm.ES256, "ES256-v20260131-101305-c1fc51b8");
        assertTrue(b);
        String keyId2 = key.getActiveKeyId();
        System.out.println("keyId1: " + keyId1 + ", keyId2: " + keyId2);
        // 切换回旧密钥
        boolean result = key.switchTo(Algorithm.HMAC512, keyId1);
        assertTrue(result);
        assertEquals(keyId1, key.getActiveKeyId());
        key.close();
    }

    private JwtProperties createValidJwtProperties() {
        return JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now().plus(1, ChronoUnit.HOURS))
                .build();
    }

    @Test
    @DisplayName("并发生成Token - 线程安全")
    void concurrentTokenGeneration_ThreadSafe() throws InterruptedException {
        boolean b = key.switchTo(Algorithm.HMAC256);
        assertTrue(b);
        int threadCount = 10;
        int iterations = 50;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        JwtProperties jwtProps = createValidJwtProperties();
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterations; j++) {
                        String token = key.generateToken(jwtProps);
                        if (token != null && key.isValidWithCurrent(token)) {
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
        key.close();
    }

    @Test
    @DisplayName("关闭后清理资源 - 成功")
    void close_CleansUpResources() {
        assertNotNull(key.getActiveKeyId());
        key.close();
        // 关闭后应该清理资源
        assertNull(key.getActiveKeyId());
    }

    @Test
    @DisplayName("多次关闭 - 不抛出异常")
    void close_MultipleTimes_NoException() {
        assertDoesNotThrow(() -> {
            key.close();
            key.close();
            key.close();
        });
    }
}
