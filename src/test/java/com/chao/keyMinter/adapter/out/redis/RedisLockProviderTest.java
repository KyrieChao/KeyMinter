package com.chao.keyMinter.adapter.out.redis;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

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
    void constructor_should_apply_defaults_when_inputs_invalid() throws Exception {
        // Arrange
        RedisLockProvider provider = new RedisLockProvider(redisTemplate, null, 0, 0, 0);

        // Act
        String lockPrefix = (String) getField(provider, "lockPrefix");
        long expireMillis = (long) getField(provider, "expireMillis");
        long retryIntervalMillis = (long) getField(provider, "retryIntervalMillis");
        long maxRetryIntervalMillis = (long) getField(provider, "maxRetryIntervalMillis");

        // Assert
        assertEquals("keyM:lock:", lockPrefix);
        assertEquals(30000L, expireMillis);
        assertEquals(100L, retryIntervalMillis);
        assertEquals(2000L, maxRetryIntervalMillis);
    }

    @Test
    void constructor_should_use_provided_values_when_inputs_valid() throws Exception {
        // Arrange
        RedisLockProvider provider = new RedisLockProvider(redisTemplate, "p:", 123, 7, 9);

        // Act
        String lockPrefix = (String) getField(provider, "lockPrefix");
        long expireMillis = (long) getField(provider, "expireMillis");
        long retryIntervalMillis = (long) getField(provider, "retryIntervalMillis");
        long maxRetryIntervalMillis = (long) getField(provider, "maxRetryIntervalMillis");

        // Assert
        assertEquals("p:", lockPrefix);
        assertEquals(123L, expireMillis);
        assertEquals(7L, retryIntervalMillis);
        assertEquals(9L, maxRetryIntervalMillis);
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
    @SuppressWarnings("unchecked")
    void testUnlock() {
        Lock lock = lockProvider.getLock("resource");
        lock.unlock();
        verify(redisTemplate).execute(any(DefaultRedisScript.class), any(List.class), anyString());
    }
    
    @Test
    void testLockBlocking() {
        // Mock setIfAbsent to return false once, then true
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false)
                .thenReturn(true);
        
        Lock lock = lockProvider.getLock("resource");
        
        // This should block for one retry then succeed
        assertDoesNotThrow(lock::lock);
        
        verify(valueOperations, times(2)).setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS));
    }
    
    @Test
    void testLockInterrupted() {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false);
        
        Lock lock = lockProvider.getLock("resource");
        
        Thread.currentThread().interrupt();
        assertThrows(RuntimeException.class, lock::lock);
        
        // Clear interrupted status for other tests
        Thread.interrupted();
    }
    
    @Test
    void testLockInterruptibly() throws InterruptedException {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false)
                .thenReturn(true);
        
        Lock lock = lockProvider.getLock("resource");
        lock.lockInterruptibly();
        
        verify(valueOperations, times(2)).setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS));
    }
    
    @Test
    void testLockInterruptiblyInterrupted() {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false);
        
        Lock lock = lockProvider.getLock("resource");
        
        Thread.currentThread().interrupt();
        assertThrows(InterruptedException.class, lock::lockInterruptibly);
        
        Thread.interrupted();
    }
    
    @Test
    void testTryLockWithTimeoutSuccess() throws InterruptedException {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(true);
        
        Lock lock = lockProvider.getLock("resource");
        assertTrue(lock.tryLock(100, TimeUnit.MILLISECONDS));
    }
    
    @Test
    void testTryLockWithTimeoutFail() throws InterruptedException {
        when(valueOperations.setIfAbsent(anyString(), anyString(), anyLong(), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(false);
        
        Lock lock = lockProvider.getLock("resource");
        assertFalse(lock.tryLock(50, TimeUnit.MILLISECONDS));
    }
    
    @Test
    void testNewCondition() {
        Lock lock = lockProvider.getLock("resource");
        assertThrows(UnsupportedOperationException.class, lock::newCondition);
    }

    private static Object getField(Object target, String fieldName) throws Exception {
        java.lang.reflect.Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(target);
    }
}
