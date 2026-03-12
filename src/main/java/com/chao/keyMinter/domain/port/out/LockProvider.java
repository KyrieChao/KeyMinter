package com.chao.keyMinter.domain.port.out;

import java.util.concurrent.locks.Lock;

/**
 * Lock Provider Interface.
 * Provides distributed or local locks for synchronization.
 */
public interface LockProvider {
    /**
     * Get a lock instance for a specific key.
     * @param key The key to lock on (e.g. a resource ID).
     * @return A Lock instance (e.g. ReentrantLock or distributed lock).
     */
    Lock getLock(String key);
}
