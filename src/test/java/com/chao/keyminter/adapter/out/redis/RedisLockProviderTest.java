package com.chao.keyminter.adapter.out.redis;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisLockProviderTest {

    @Mock
    StringRedisTemplate redisTemplate;

    @Mock
    ValueOperations<String, String> valueOperations;

    private RedisLockProvider lockProvider;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        lockProvider = new RedisLockProvider(redisTemplate, "test:lock:", 1000);
    }

    @Test
    void testGetLock() {
        Lock lock = lockProvider.getLock("resource");
        assertNotNull(lock);
    }

    @Test
    void testTryLockSuccess() {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(true);

        Lock lock = lockProvider.getLock("resource");
        assertTrue(lock.tryLock());

        verify(valueOperations).setIfAbsent(eq("test:lock:resource"), anyString(), eq(1000L), eq(TimeUnit.MILLISECONDS));
    }

    @Test
    void testTryLockFail() {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false);

        Lock lock = lockProvider.getLock("resource");
        assertFalse(lock.tryLock());
    }

    @Test
    void testUnlock() {
        Lock lock = lockProvider.getLock("resource");
        lock.unlock();

        verify(redisTemplate).execute(any(DefaultRedisScript.class), any(List.class), anyString());
    }
}
