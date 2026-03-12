package com.chao.keyminter.adapter.in.spring;

import com.chao.keyminter.api.KeyMinter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KeyMinterHealthIndicatorTest {

    @Mock
    KeyMinter keyMinter;

    @InjectMocks
    private KeyMinterHealthIndicator healthIndicator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testHealthUp() {
        // Mock successful health check dependencies
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getActiveKeyId()).thenReturn("key-1");
        when(keyMinter.getKeyPath()).thenReturn(Path.of("."));
        when(keyMinter.getCacheSize()).thenReturn(1);
        when(keyMinter.getAlgorithmInfo()).thenReturn("HMAC256");

        Health health = healthIndicator.health();
        
        assertEquals(Status.UP, health.getStatus());
        assertEquals("key-1", health.getDetails().get("activeKeyId"));
        assertEquals(1, health.getDetails().get("cacheSize"));
    }
    
    @Test
    void testHealthDown() {
        // Mock failure
        when(keyMinter.keyPairExists()).thenReturn(false);
        
        Health health = healthIndicator.health();
        
        assertEquals(Status.DOWN, health.getStatus());
    }
    
    @Test
    void testHealthException() {
        when(keyMinter.keyPairExists()).thenThrow(new RuntimeException("Error"));
        
        Health health = healthIndicator.health();
        
        assertEquals(Status.DOWN, health.getStatus());
        assertNotNull(health.getDetails().get("error"));
    }
}
