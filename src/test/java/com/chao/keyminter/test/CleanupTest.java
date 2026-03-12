package com.chao.keyminter.test;

import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.core.AbstractJwtAlgo;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.KeyStatus;
import com.chao.keyminter.domain.model.KeyVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyMinter Cleanup Tests")
class CleanupTest {

    @TempDir
    Path tempDir;

    private JwtFactory factory;
    private KeyMinter keyMinter;

    @BeforeEach
    void setUp() {
        KeyMinterProperties properties = new KeyMinterProperties();
        // Enable auto cleanup logic in AbstractJwtAlgo (though we call it manually via scheduledCleanup)
        properties.setAutoCleanupExpiredKeys(true);
        properties.setEnableRotation(true);
        properties.setKeyDir("C:\\Users\\dell\\.keyminter-test-env");
        factory = new JwtFactory();
        factory.setProperties(properties);
        keyMinter = new KeyMinter(factory);
    }

    @Test
    @DisplayName("Test: Cleanup specific directory (Custom Path)")
    void testCleanupSpecificDirectory() throws Exception {
        // 1. 指定自定义目录
        Path customDir = Path.of("C:\\Users\\dell\\.keyminter-test-env");
        // 确保目录存在
        if (!Files.exists(customDir)) {
            Files.createDirectories(customDir);
        }

        // 这里为了演示，我们先初始化到这个目录
        // 强制开启自动加载，以防之前状态干扰
//        keyMinter.switchTo(Algorithm.HMAC256, customDir.toString(), null, true);

        // 2. 创建并激活 Key A
//        boolean created = keyMinter.createHmacKey(Algorithm.HMAC256, 64);
//        assertTrue(created, "Key creation failed");

        // 重新获取 algo，确保它指向正确目录
        JwtAlgo algo = factory.get(Algorithm.HMAC256, customDir);

        // 确保内部状态已更新
        algo.loadExistingKeyVersions();

        Map<String, KeyVersion> internalMap = getInternalKeyVersionsMap(algo);

        // Retry logic
        if (internalMap.isEmpty()) {
             // Fallback: manually list files to debug
             System.out.println("DEBUG: Listing files in " + algo.getKeyPath());
             if (Files.exists(algo.getKeyPath())) {
                 Files.list(algo.getKeyPath()).forEach(System.out::println);
             } else {
                 System.out.println("DEBUG: Directory does not exist: " + algo.getKeyPath());
             }

             // 尝试再次创建
             keyMinter.createHmacKey(Algorithm.HMAC256, 64);
             algo.loadExistingKeyVersions();
             internalMap = getInternalKeyVersionsMap(algo);

             if (internalMap.isEmpty()) {
                 throw new IllegalStateException("No keys found in custom dir even after retry. Directory: " + algo.getKeyPath());
             }
        }

        String keyAId = internalMap.keySet().stream().findFirst().orElseThrow(() -> new IllegalStateException("No keys found in custom dir"));
        keyMinter.setActiveKey(keyAId);

        // 3. 模拟 Key A 过期
        KeyVersion keyA = internalMap.get(keyAId);
        keyA.setExpiresAt(Instant.now().minusSeconds(1));

        // 4. 执行清理
        keyMinter.scheduledCleanup();
        
        // 5. 验证状态
        assertEquals(KeyStatus.EXPIRED, keyA.getStatus(), "Key in custom directory should be expired");
    }

    @Test
    @DisplayName("Test: Cleanup specific directory (Custom Path)")
    void testCleanupSpecificDirectory2() {
        keyMinter.switchTo(Algorithm.RSA256);
        keyMinter.scheduledCleanup();
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

    @SuppressWarnings("unchecked")
    private Map<String, KeyVersion> getInternalKeyVersionsMap(JwtAlgo algo) throws Exception {
        if (algo instanceof AbstractJwtAlgo) {
            Field field = AbstractJwtAlgo.class.getDeclaredField("keyVersions");
            field.setAccessible(true);
            return (Map<String, KeyVersion>) field.get(algo);
        }
        throw new IllegalStateException("Algo is not AbstractJwtAlgo");
    }

    @Test
    @DisplayName("Test: Expired keys should be marked as EXPIRED")
    void testCleanupExpiredKeys() throws Exception {
        // 1. Initialize and create a key
        keyMinter.switchTo(Algorithm.HMAC256, tempDir, true);
        keyMinter.createHmacKey(Algorithm.HMAC256, 64);
        
        // 2. Get the internal map
        JwtAlgo algo = factory.get(Algorithm.HMAC256);
        Map<String, KeyVersion> internalMap = getInternalKeyVersionsMap(algo);
        
        assertFalse(internalMap.isEmpty(), "Internal map should have keys");
        String keyId = internalMap.keySet().iterator().next();
        KeyVersion key = internalMap.get(keyId);

        // Manually activate if needed
        if (key.getStatus() == KeyStatus.CREATED) {
            keyMinter.setActiveKey(keyId);
            // Refresh key object from map as it might have been replaced or updated
            key = internalMap.get(keyId);
        }
        
        assertEquals(KeyStatus.ACTIVE, key.getStatus(), "Key should be active");

        // 3. Manually expire the key in the INTERNAL MAP
        key.setExpiresAt(Instant.now().minusSeconds(1));

        // 4. Run cleanup
        keyMinter.scheduledCleanup();

        // 5. Verify status
        assertEquals(KeyStatus.EXPIRED, key.getStatus(), "Key should be marked as EXPIRED");
    }

    @Test
    @DisplayName("Test: Transitioning keys should be deactivated after transition period")
    void testCleanupTransitioningKeys() throws Exception {
        // 1. Initialize
        keyMinter.switchTo(Algorithm.HMAC256, tempDir, false);

        // 2. Create Key A and Activate it
        keyMinter.createHmacKey(Algorithm.HMAC256, 64);
        
        JwtAlgo algo = factory.get(Algorithm.HMAC256);
        Map<String, KeyVersion> internalMap = getInternalKeyVersionsMap(algo);
        
        // Get Key A ID
        String keyAId = internalMap.keySet().iterator().next();
        keyMinter.setActiveKey(keyAId);
        
        KeyVersion keyA = internalMap.get(keyAId);
        assertEquals(KeyStatus.ACTIVE, keyA.getStatus());

        // 3. Create Key B and Activate it (Triggering transition for Key A)
        try { Thread.sleep(100); } catch (InterruptedException e) {} // Wait longer to ensure timestamp diff if that matters
        boolean created = keyMinter.createHmacKey(Algorithm.HMAC256, 64);
        assertTrue(created, "Key B creation failed");
        
        // Find Key B
        String keyBId = internalMap.keySet().stream()
                .filter(id -> !id.equals(keyAId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Key B not found. Map: " + internalMap.keySet()));
                
        // Activate Key B
        keyMinter.setActiveKey(keyBId);
        KeyVersion keyB = internalMap.get(keyBId);

        // 4. Verify Key A is TRANSITIONING
        assertEquals(KeyStatus.TRANSITIONING, keyA.getStatus(), "Key A should be TRANSITIONING");
        assertEquals(KeyStatus.ACTIVE, keyB.getStatus(), "Key B should be ACTIVE");

        // 5. Set Key A transition end time to past IN THE INTERNAL MAP
        keyA.startTransition(Instant.now().minusSeconds(1)); 

        // 6. Run cleanup
        keyMinter.scheduledCleanup();

        // 7. Verify Key A is INACTIVE
        assertEquals(KeyStatus.INACTIVE, keyA.getStatus(), "Key A should be INACTIVE after transition period");
    }
}
