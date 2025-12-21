package key_minter.security;

import java.lang.ref.Cleaner;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.StampedLock;

/**
 * 线程安全的安全密钥管理器
 */
public class SecureSecretManager {

    private static final Cleaner CLEANER = Cleaner.create();
    private final ConcurrentMap<String, ManagedSecret> secrets = new ConcurrentHashMap<>();

    /**
     * 托管的秘密 - 自动清理
     */
    private static class ManagedSecret implements Runnable {
        private final String keyId;
        private final SecureSecret secret;
        private final StampedLock lock = new StampedLock();

        ManagedSecret(String keyId, SecureSecret secret) {
            this.keyId = keyId;
            this.secret = secret;
            // 注册清理器
            CLEANER.register(this, this);
        }

        byte[] getBytes() {
            long stamp = lock.readLock();
            try {
                return secret.getBytes();
            } finally {
                lock.unlockRead(stamp);
            }
        }

        void update(SecureSecret newSecret) {
            long stamp = lock.writeLock();
            try {
                secret.wipe();
                // 注意：这里不能直接赋值，因为ManagedSecret不可变
                // 实际应该创建新的ManagedSecret
            } finally {
                lock.unlockWrite(stamp);
            }
        }

        void wipe() {
            long stamp = lock.writeLock();
            try {
                secret.wipe();
            } finally {
                lock.unlockWrite(stamp);
            }
        }

        @Override
        public void run() {
            // Cleaner回调时自动清理
            wipe();
        }
    }

    /**
     * 存储密钥
     */
    public void store(String keyId, SecureSecret secret) {
        secrets.put(keyId, new ManagedSecret(keyId, secret));
    }

    /**
     * 获取密钥（使用后自动清理副本）
     */
    public <T> T useSecret(String keyId, SecretConsumer<T> consumer) {
        ManagedSecret managed = secrets.get(keyId);
        if (managed == null) {
            throw new IllegalArgumentException("Secret not found: " + keyId);
        }

        byte[] secretBytes = managed.getBytes();
        try {
            return consumer.consume(secretBytes);
        } finally {
            // 清理临时数组
            if (secretBytes != null) {
                Arrays.fill(secretBytes, (byte) 0);
            }
        }
    }

    /**
     * 安全地使用密钥（lambda形式）
     */
    @FunctionalInterface
    public interface SecretConsumer<T> {
        T consume(byte[] secretBytes);
    }

    /**
     * 移除并清理密钥
     */
    public void remove(String keyId) {
        ManagedSecret removed = secrets.remove(keyId);
        if (removed != null) {
            removed.wipe();
        }
    }

    /**
     * 清理所有密钥
     */
    public void clear() {
        secrets.values().forEach(ManagedSecret::wipe);
        secrets.clear();
    }
}