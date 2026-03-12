package com.chao.keyMinter.internal;

import java.lang.ref.Cleaner;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.StampedLock;

/**
 * Secure Secret Manager.
 * Manages secure secrets in memory with auto-wiping capabilities.
 */
class SecureSecretManager {

    private static final Cleaner CLEANER = Cleaner.create();
    private final ConcurrentMap<String, ManagedSecret> secrets = new ConcurrentHashMap<>();

    /**
     * Managed Secret Wrapper.
     */
    private static class ManagedSecret implements Runnable {
        private final SecureSecret secret;
        private final StampedLock lock = new StampedLock();

        ManagedSecret(String keyId, SecureSecret secret) {
            this.secret = secret;
            // Register for cleaning
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
            // Cleaner action
            wipe();
        }
    }

    /**
     * Store a secret.
     */
    public void store(String keyId, SecureSecret secret) {
        secrets.put(keyId, new ManagedSecret(keyId, secret));
    }

    /**
     * Update a secret, wiping the old one.
     */
    public void update(String keyId, SecureSecret newSecret) {
        ManagedSecret old = secrets.get(keyId);
        if (old != null) {
            old.wipe();
        }
        secrets.put(keyId, new ManagedSecret(keyId, newSecret));
    }

    /**
     * Execute a function with the secret bytes, ensuring they are wiped afterwards.
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
            // Wipe the temporary copy
            if (secretBytes != null) {
                Arrays.fill(secretBytes, (byte) 0);
            }
        }
    }

    /**
     * Functional interface for consuming secret bytes.
     */
    @FunctionalInterface
    public interface SecretConsumer<T> {
        T consume(byte[] secretBytes);
    }

    /**
     * Remove and wipe a secret.
     */
    public void remove(String keyId) {
        ManagedSecret removed = secrets.remove(keyId);
        if (removed != null) {
            removed.wipe();
        }
    }

    /**
     * Clear and wipe all secrets.
     */
    public void clear() {
        secrets.values().forEach(ManagedSecret::wipe);
        secrets.clear();
    }
}
