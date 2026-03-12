package com.chao.keyMinter.adapter.out.redis;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RedisRevocationStoreTest {

    @Mock
    StringRedisTemplate redisTemplate;

    @Mock
    ValueOperations<String, String> valueOperations;

    private RedisRevocationStore store;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        store = new RedisRevocationStore(redisTemplate, "jwt:revoked:");
    }

    @Test
    void testRevoke() {
        String fingerprint = "fp123";
        long expiryTime = System.currentTimeMillis() + 10000;

        store.revoke(fingerprint, expiryTime);

        verify(valueOperations).set(
                eq("jwt:revoked:" + fingerprint),
                eq(String.valueOf(expiryTime)),
                anyLong(),
                eq(TimeUnit.MILLISECONDS)
        );
    }
    
    @Test
    void testRevokeAlreadyExpired() {
        String fingerprint = "fp123";
        long expiryTime = System.currentTimeMillis() - 10000;

        store.revoke(fingerprint, expiryTime);

        // Should not set to redis
        verify(valueOperations, never()).set(anyString(), anyString(), anyLong(), any());
    }

    @Test
    void testIsRevoked() {
        String fingerprint = "fp123";
        long futureTime = System.currentTimeMillis() + 10000;
        
        // Case 1: Active revocation
        when(valueOperations.get("jwt:revoked:" + fingerprint)).thenReturn(String.valueOf(futureTime));
        assertTrue(store.isRevoked(fingerprint));
        
        // Case 2: No revocation record
        when(valueOperations.get("jwt:revoked:" + fingerprint)).thenReturn(null);
        assertFalse(store.isRevoked(fingerprint));

        // Case 3: Expired revocation (should trigger cleanup)
        long pastTime = System.currentTimeMillis() - 10000;
        when(valueOperations.get("jwt:revoked:" + fingerprint)).thenReturn(String.valueOf(pastTime));
        assertFalse(store.isRevoked(fingerprint));
        verify(redisTemplate).delete("jwt:revoked:" + fingerprint);
    }
    
    @Test
    void testIsRevokedInvalidFormat() {
        String fingerprint = "fp-invalid";
        when(valueOperations.get("jwt:revoked:" + fingerprint)).thenReturn("invalid-timestamp");
        
        assertFalse(store.isRevoked(fingerprint));
        verify(redisTemplate).delete("jwt:revoked:" + fingerprint);
    }
}
