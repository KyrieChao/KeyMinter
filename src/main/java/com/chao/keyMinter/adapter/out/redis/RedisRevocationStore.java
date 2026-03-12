package com.chao.keyMinter.adapter.out.redis;

import com.chao.keyMinter.domain.port.out.RevocationStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.concurrent.TimeUnit;

/**
 * Redis-based revocation store.
 */
@Slf4j
@RequiredArgsConstructor
public class RedisRevocationStore implements RevocationStore {

    private final StringRedisTemplate redisTemplate;
    private final String keyPrefix;

    @Override
    public void revoke(String fingerprint, long until) {
        long now = System.currentTimeMillis();
        long ttl = until - now;
        if (ttl > 0) {
            String key = keyPrefix + fingerprint;
            redisTemplate.opsForValue().set(key, String.valueOf(until), ttl, TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public boolean isRevoked(String fingerprint) {
        String key = keyPrefix + fingerprint;
        String value = redisTemplate.opsForValue().get(key);
        
        if (value == null) return false;
        try {
            long until = Long.parseLong(value);
            if (System.currentTimeMillis() > until) {
                // Should rely on Redis TTL, but double check just in case
                redisTemplate.delete(key);
                return false;
            }
            return true; 
        } catch (NumberFormatException e) {
            log.warn("Invalid revocation data for fingerprint: {}, cleaning up", fingerprint);
            redisTemplate.delete(key);
            return false;
        }
    }
}
