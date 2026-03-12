package com.chao.keyminter.api;

import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class KeyMinterTest {

    @Mock
    JwtFactory jwtFactory;

    @Mock
    JwtAlgo defaultAlgo;

    @Mock
    JwtAlgo newAlgo;

    private KeyMinter keyMinter;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("Default Algo Info");

        keyMinter = new KeyMinter(jwtFactory);
    }

    @Test
    void testInitialization() {
        verify(jwtFactory).get(Algorithm.HMAC256);
        assertEquals("Default Algo Info", keyMinter.getJwtProperties());
    }

    @Test
    void testSwitchTo() {
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("New Algo Info");

        boolean result = keyMinter.switchTo(Algorithm.RSA256);
        assertTrue(result);

        assertEquals("New Algo Info", keyMinter.getJwtProperties());
        // Verify graceful period setup (internal state, hard to verify directly without reflection or behavior)
        // But we can verify that previous algo is closed on cleanup
    }

    @Test
    void testSwitchToWithPath() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.get(Algorithm.ES256, path)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("EC Algo Info");

        boolean result = keyMinter.switchTo(Algorithm.ES256, path, false);
        assertTrue(result);

        assertEquals("EC Algo Info", keyMinter.getJwtProperties());
    }

    @Test
    void testGenerateToken() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");

        when(defaultAlgo.generateToken(any(), eq(Algorithm.HMAC256))).thenReturn("token");

        String token = keyMinter.generateToken(props);
        assertEquals("token", token);
        verify(defaultAlgo).generateToken(any(), eq(Algorithm.HMAC256));
    }

    @Test
    void testVerifyToken() {
        when(defaultAlgo.verifyToken("valid-token")).thenReturn(true);
        when(defaultAlgo.verifyToken("invalid-token")).thenReturn(false);

        assertTrue(keyMinter.isValidToken("valid-token"));
        assertFalse(keyMinter.isValidToken("invalid-token"));
    }

    @Test
    void testGracefulVerify() {
        // Setup: Switch from default to new
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        keyMinter.switchTo(Algorithm.RSA256);

        // Current is newAlgo, Previous is defaultAlgo

        // Case 1: Token valid with current
        when(newAlgo.verifyToken("token1")).thenReturn(true);
        assertTrue(keyMinter.isValidToken("token1"));
        verify(defaultAlgo, never()).verifyToken("token1");

        // Case 2: Token invalid with current, valid with previous
        when(newAlgo.verifyToken("token2")).thenReturn(false);
        when(defaultAlgo.verifyToken("token2")).thenReturn(true);
        assertTrue(keyMinter.isValidToken("token2"));

        // Case 3: Token invalid with both
        when(newAlgo.verifyToken("token3")).thenReturn(false);
        when(defaultAlgo.verifyToken("token3")).thenReturn(false);
        assertFalse(keyMinter.isValidToken("token3"));
    }

    @Test
    void testScheduledCleanup() {
        keyMinter.scheduledCleanup();
        verify(jwtFactory).cleanupAllAlgos();
        // Can't easily verify graceful cleanup without waiting or mocking time
    }

    @Test
    void testAutoLoadDelegation() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519)).thenReturn(newAlgo);
        JwtAlgo result = keyMinter.autoLoad(Algorithm.Ed25519);
        assertSame(newAlgo, result);
        verify(jwtFactory).autoLoad(Algorithm.Ed25519);
    }
}
