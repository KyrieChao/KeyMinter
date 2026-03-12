package com.chao.keyMinter.adapter.out.redis;

import com.chao.keyMinter.domain.port.out.LockProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

/**
 * Redis distributed lock implementation.
 */
public class RedisLockProvider implements LockProvider {

    private final StringRedisTemplate redisTemplate;
    private final String lockPrefix;
    private final long expireMillis;
    private final long retryIntervalMillis;
    private final long maxRetryIntervalMillis;

    public RedisLockProvider(StringRedisTemplate redisTemplate, String lockPrefix, long expireMillis) {
        this(redisTemplate, lockPrefix, expireMillis, 100, 2000);
    }

    public RedisLockProvider(StringRedisTemplate redisTemplate, String lockPrefix, long expireMillis, long retryIntervalMillis, long maxRetryIntervalMillis) {
        this.redisTemplate = redisTemplate;
        this.lockPrefix = lockPrefix != null ? lockPrefix : "keyM:lock:";
        this.expireMillis = expireMillis > 0 ? expireMillis : 30000; // Default 30s
        this.retryIntervalMillis = retryIntervalMillis > 0 ? retryIntervalMillis : 100;
        this.maxRetryIntervalMillis = maxRetryIntervalMillis > 0 ? maxRetryIntervalMillis : 2000;
    }

    @Override
    public Lock getLock(String key) {
        return new RedisLock(redisTemplate, lockPrefix + key, expireMillis, retryIntervalMillis, maxRetryIntervalMillis);
    }

    private static class RedisLock implements Lock {
        private final StringRedisTemplate redisTemplate;
        private final String lockKey;
        private final long expireMillis;
        private final String lockValue;
        private final long initialRetryInterval;
        private final long maxRetryInterval;
        
        // Lua script for safe unlock
        private static final String UNLOCK_SCRIPT = 
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

        public RedisLock(StringRedisTemplate redisTemplate, String lockKey, long expireMillis, long initialRetryInterval, long maxRetryInterval) {
            this.redisTemplate = redisTemplate;
            this.lockKey = lockKey;
            this.expireMillis = expireMillis;
            this.lockValue = UUID.randomUUID().toString();
            this.initialRetryInterval = initialRetryInterval;
            this.maxRetryInterval = maxRetryInterval;
        }

        @Override
        public void lock() {
            long retryDelay = initialRetryInterval;
            // Exponential Backoff
            while (!tryLock()) {
                try {
                    Thread.sleep(retryDelay);
                    retryDelay = Math.min(retryDelay * 2, maxRetryInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Interrupted while acquiring lock", e);
                }
            }
        }

        @Override
        public void lockInterruptibly() throws InterruptedException {
            while (!tryLock()) {
                if (Thread.interrupted()) {
                    throw new InterruptedException();
                }
                Thread.sleep(100);
            }
        }

        @Override
        public boolean tryLock() {
            Boolean success = redisTemplate.opsForValue().setIfAbsent(lockKey, lockValue, expireMillis, TimeUnit.MILLISECONDS);
            return Boolean.TRUE.equals(success);
        }

        @Override
        public boolean tryLock(long time, TimeUnit unit) throws InterruptedException {
            long start = System.currentTimeMillis();
            long maxWait = unit.toMillis(time);
            
            while (true) {
                if (tryLock()) {
                    return true;
                }
                long now = System.currentTimeMillis();
                if (now - start >= maxWait) {
                    return false;
                }
                Thread.sleep(Math.min(100, maxWait - (now - start)));
            }
        }

        @Override
        public void unlock() {
            DefaultRedisScript<Long> script = new DefaultRedisScript<>(UNLOCK_SCRIPT, Long.class);
            redisTemplate.execute(script, Collections.singletonList(lockKey), lockValue);
        }

        @Override
        public  Condition newCondition() {
            throw new UnsupportedOperationException("Conditions are not supported by RedisLock");
        }
    }
}
