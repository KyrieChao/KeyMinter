package com.chao.keyminter.adapter.out.redis;

import com.chao.keyminter.domain.port.out.RevocationStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * 基于 Redis 的撤销存储实现
 */
@Slf4j
@Component
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
        // 从未撤销或已过期自动删除
        if (value == null) return false;
        try {
            // 检查 until 时间戳，防止 Redis 过期策略延迟
            long until = Long.parseLong(value);
            if (System.currentTimeMillis() > until) {
                // 已过期但 Redis 还没删，主动清理（异步，不阻塞）
                redisTemplate.delete(key);
                return false;
            }
            return true;  // 明确的撤销记录
        } catch (NumberFormatException e) {
            // 数据损坏，清理并视为未撤销
            log.warn("Invalid revocation data for fingerprint: {}, cleaning up", fingerprint);
            redisTemplate.delete(key);
            return false;
        }
    }
}
