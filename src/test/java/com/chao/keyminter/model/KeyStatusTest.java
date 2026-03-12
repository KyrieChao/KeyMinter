package com.chao.keyminter.model;

import jakarta.annotation.Resource;
import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.adapter.in.spring.KeyMinterAutoConfiguration;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.KeyStatus;
import com.chao.keyminter.domain.model.KeyVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyStatus 枚举的单元测试
 * 覆盖所有状态判断逻辑及基本属性
 */
@SpringBootTest(classes = KeyMinterAutoConfiguration.class)
public class KeyStatusTest {
    @Resource
    private KeyMinter key;

    @Test
    @DisplayName("验证密钥轮换后旧密钥进入 TRANSITIONING 状态")
    void shouldTransitionOldKeyStatus() {
        // 1. 确保 RSA 密钥存在 (如果不存在则创建，如果存在则可能是旧的)
        // createKeyPair 会在默认 RSA 目录生成密钥
        boolean created = key.createKeyPair(Algorithm.RSA256);
        System.out.println("第一次创建密钥结果: " + created);

        // 2. 切换 KeyMinter 到 RSA 模式
        // 此时密钥已存在，switchTo 应成功
        boolean switched = key.switchTo(Algorithm.RSA256);
        assertTrue(switched, "切换到 RSA256 失败，可能是密钥创建失败");

        String firstKeyId = key.getActiveKeyId();
        assertNotNull(firstKeyId, "初始密钥ID不应为空");
        System.out.println("当前活跃密钥: " + firstKeyId);

        // 3. 触发轮换
        // 再次创建密钥，会触发轮换
        assertTrue(key.createKeyPair(Algorithm.RSA256));
        
        String secondKeyId = key.getActiveKeyId();
        assertNotEquals(firstKeyId, secondKeyId, "轮换后密钥ID应改变");
        System.out.println("轮换后新活跃密钥: " + secondKeyId);

        // 4. 验证旧密钥状态
        // listKeys() 默认扫描默认目录，可能与当前配置的目录不同
        // 所以我们需要显式指定当前使用的目录的父目录
        Path currentKeyDir = key.getKeyPath();
        Path baseDir = currentKeyDir.getParent();
        
        List<KeyVersion> allKeys = key.listKeys(Algorithm.RSA256, baseDir.toString());
        
        KeyVersion oldVersion = allKeys.stream()
                .filter(k -> k.getKeyId().equals(firstKeyId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("未找到旧密钥: " + firstKeyId + " in " + baseDir));
        
        assertEquals(KeyStatus.TRANSITIONING, oldVersion.getStatus(), "旧密钥应处于 TRANSITIONING 状态");
        System.out.println("验证成功：旧密钥 " + firstKeyId + " 状态为 TRANSITIONING");
        
        key.close();
    }

    @Test
    @DisplayName("生成包含所有状态密钥的文件夹结构 (ACTIVE, TRANSITIONING, EXPIRED, REVOKED, INACTIVE, CREATED)")
    void shouldGenerateAllKeyStatuses() throws IOException {
        // 1. 设置基础目录
        Path baseDir = Path.of("target/key-status-full-demo");
        if (!Files.exists(baseDir)) {
            Files.createDirectories(baseDir);
        }

        // 2. 初始化环境：手动加载算法并生成第一个密钥，确保 switch 成功
        JwtAlgo algo = key.autoLoad(Algorithm.RSA256, baseDir);
        algo.generateKeyPair(Algorithm.RSA256);
        
        // 3. 切换 KeyMinter 到该目录
        assertTrue(key.switchTo(Algorithm.RSA256, baseDir, true));

        // 此时已有一个 ACTIVE 密钥 (K1)
        String k1 = key.getActiveKeyId();
        System.out.println("K1 (Active): " + k1);

        // 4. 生成 TRANSITIONING (K1)
        // 注意：必须使用 algo 实例调用 generateKeyPair，因为 key.createKeyPair() 默认使用默认目录
        algo.generateKeyPair(Algorithm.RSA256);
        String k2 = key.getActiveKeyId(); // K2 is Active, K1 is Transitioning
        System.out.println("K2 (Active): " + k2);
        assertNotEquals(k1, k2, "Key ID should change after rotation");

        // 5. 生成 EXPIRED (K2)
        algo.generateKeyPair(Algorithm.RSA256);
        String k3 = key.getActiveKeyId(); // K3 is Active, K2 is Transitioning
        System.out.println("K3 (Active): " + k3);
        assertNotEquals(k2, k3);
        
        // 修改 K2 为 EXPIRED
        Path k2Dir = baseDir.resolve("rsa-keys").resolve(k2);
        Files.writeString(k2Dir.resolve("expiration.info"), Instant.now().minusSeconds(3600).toString());
        Files.writeString(k2Dir.resolve("status.info"), KeyStatus.EXPIRED.name());

        // 6. 生成 REVOKED (K3)
        algo.generateKeyPair(Algorithm.RSA256);
        String k4 = key.getActiveKeyId(); // K4 is Active, K3 is Transitioning
        System.out.println("K4 (Active): " + k4);
        assertNotEquals(k3, k4);
        
        // 修改 K3 为 REVOKED
        Path k3Dir = baseDir.resolve("rsa-keys").resolve(k3);
        Files.writeString(k3Dir.resolve("status.info"), KeyStatus.REVOKED.name());

        // 7. 生成 INACTIVE (K4)
        algo.generateKeyPair(Algorithm.RSA256);
        String k5 = key.getActiveKeyId(); // K5 is Active, K4 is Transitioning
        System.out.println("K5 (Active): " + k5);
        assertNotEquals(k4, k5);
        
        // 修改 K4 为 INACTIVE
        Path k4Dir = baseDir.resolve("rsa-keys").resolve(k4);
        Files.writeString(k4Dir.resolve("status.info"), KeyStatus.INACTIVE.name());

        // 8. 生成 CREATED (K5)
        algo.generateKeyPair(Algorithm.RSA256);
        String k6 = key.getActiveKeyId(); // K6 is Active, K5 is Transitioning
        System.out.println("K6 (Active): " + k6);
        assertNotEquals(k5, k6);
        
        // 修改 K5 为 CREATED
        Path k5Dir = baseDir.resolve("rsa-keys").resolve(k5);
        Files.writeString(k5Dir.resolve("status.info"), KeyStatus.CREATED.name());
        
        // 9. 验证所有状态
        java.util.List<KeyVersion> allKeys = key.listKeys(Algorithm.RSA256, baseDir.toString());
        System.out.println("Generated keys: " + allKeys);

        assertKeyStatus(allKeys, k1, KeyStatus.TRANSITIONING);
        assertKeyStatus(allKeys, k2, KeyStatus.EXPIRED);
        assertKeyStatus(allKeys, k3, KeyStatus.REVOKED);
        assertKeyStatus(allKeys, k4, KeyStatus.INACTIVE);
        assertKeyStatus(allKeys, k5, KeyStatus.CREATED);
        assertKeyStatus(allKeys, k6, KeyStatus.ACTIVE);

        key.close();
    }

    private void assertKeyStatus(java.util.List<KeyVersion> keys, String keyId, KeyStatus expectedStatus) {
        KeyVersion kv = keys.stream()
                .filter(k -> k.getKeyId().equals(keyId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Key not found: " + keyId));
        assertEquals(expectedStatus, kv.getStatus(), "Key " + keyId + " status mismatch");
    }
}
