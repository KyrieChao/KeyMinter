package com.chao.keyminter.api;

import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.port.out.RevocationStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class RenewalTest {

    @Mock
    KeyMinter keyMinter;

    @Mock
    RevocationStore revocationStore;

    private Renewal renewal;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        renewal = new Renewal(keyMinter, revocationStore);
    }

    @Test
    void testRefreshInGracePeriodSuccess() {
        String token = "valid-token";
        JwtProperties props = new JwtProperties();

        when(keyMinter.isValidWithGraceful(token)).thenReturn(true);
        when(revocationStore.isRevoked(anyString())).thenReturn(false);
        when(keyMinter.generateToken(props)).thenReturn("new-token");

        String newToken = renewal.refreshInGracePeriod(token, props);
        assertEquals("new-token", newToken);
    }

    @Test
    void testRefreshInGracePeriodRevoked() {
        String token = "revoked-token";
        JwtProperties props = new JwtProperties();

        when(keyMinter.isValidWithGraceful(token)).thenReturn(true);
        when(revocationStore.isRevoked(anyString())).thenReturn(true);

        String newToken = renewal.refreshInGracePeriod(token, props);
        assertNull(newToken);
        verify(keyMinter).recordBlacklistHit();
    }

    @Test
    void testRefreshInGracePeriodInvalid() {
        String token = "invalid-token";
        JwtProperties props = new JwtProperties();

        when(keyMinter.isValidWithGraceful(token)).thenReturn(false);

        String newToken = renewal.refreshInGracePeriod(token, props);
        assertNull(newToken);
    }

    @Test
    void testRevokeToken() {
        String token = "token-to-revoke";
        Date expiry = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

        when(keyMinter.decodeExpiration(token)).thenReturn(expiry);

        boolean result = renewal.revokeToken(token);
        assertTrue(result);
        verify(revocationStore).revoke(anyString(), eq(expiry.getTime()));
    }

    @Test
    void testRevokeTokenNoExpiry() {
        String token = "token-no-exp";
        when(keyMinter.decodeExpiration(token)).thenReturn(null);

        boolean result = renewal.revokeToken(token);
        assertFalse(result);
        verify(revocationStore, never()).revoke(anyString(), anyLong());
    }

    @Test
    void testRefreshNearExpiry() {
        String token = "near-expiry-token";
        JwtProperties props = new JwtProperties();
        Date expiry = Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)); // Expiring in 5 mins

        when(keyMinter.isTokenDecodable(token)).thenReturn(true);
        when(revocationStore.isRevoked(anyString())).thenReturn(false);
        when(keyMinter.decodeExpiration(token)).thenReturn(expiry);
        when(keyMinter.generateToken(props)).thenReturn("new-token");

        // Advance 10 minutes, so it is within 10 minutes window
        String newToken = renewal.refreshNearExpiry(token, props, 600000); // 10 mins
        assertEquals("new-token", newToken);
    }

    @Test
    void testRefreshNearExpiryNotNear() {
        String token = "fresh-token";
        JwtProperties props = new JwtProperties();
        Date expiry = Date.from(Instant.now().plus(1, ChronoUnit.HOURS)); // Expiring in 1 hour

        when(keyMinter.isTokenDecodable(token)).thenReturn(true);
        when(revocationStore.isRevoked(anyString())).thenReturn(false);
        when(keyMinter.decodeExpiration(token)).thenReturn(expiry);

        String newToken = renewal.refreshNearExpiry(token, props, 600000); // 10 mins
        assertNull(newToken);
    }
}
