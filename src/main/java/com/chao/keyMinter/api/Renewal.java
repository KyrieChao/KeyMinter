package com.chao.keyMinter.api;

import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.port.out.RevocationStore;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class Renewal {
    private final KeyMinter key;
    private final RevocationStore revocationStore;

    /**
     * Refresh token during grace period.
     * Returns a new token if the old token is valid within the grace period and not revoked.
     */
    public String refreshInGracePeriod(String token, JwtProperties properties) {
        if (!key.isValidWithGraceful(token) || isRevoked(token)) return null;
        return key.generateToken(properties);
    }

    public <T> String refreshInGracePeriod(String token, JwtProperties properties, T claims, Class<T> clazz) {
        if (!key.isValidWithGraceful(token) || isRevoked(token)) return null;
        return key.generateToken(properties, claims, clazz);
    }

    /**
     * Refresh token if it is nearing expiration.
     */
    public String refreshNearExpiry(String token, JwtProperties properties, long advanceMs) {
        if (!canRefreshNearExpiry(token, advanceMs)) return null;
        return key.generateToken(properties);
    }

    public <T> String refreshNearExpiry(String token, JwtProperties properties, long advanceMs, T claims, Class<T> clazz) {
        if (!canRefreshNearExpiry(token, advanceMs)) return null;
        return key.generateToken(properties, claims, clazz);
    }

    /**
     * Refresh token if near expiry and revoke the old one.
     * This implements "Rotation" strategy where the old token is blacklisted.
     */
    public String refreshNearExpiryWithRevoke(String token, JwtProperties properties, long advanceMs) {
        if (!isNearExpiry(token, advanceMs) || !key.isTokenDecodable(token)) return null;
        // Generate new token first
        String newToken;
        try {
            newToken = key.generateToken(properties);
        } catch (Exception e) {
            return null;
        }
        // If successful, revoke old token
        if (newToken != null) revokeToken(token);
        return newToken;
    }

    public <T> String refreshNearExpiryWithRevoke(String token, JwtProperties properties, long advanceMs, T claims, Class<T> clazz) {
        if (!key.isValidWithGraceful(token)) return null;
        String newToken;
        try {
            newToken = key.generateToken(properties);
        } catch (Exception e) {
            return null;
        }
        if (newToken != null) revokeToken(token);
        return newToken;
    }

    /**
     * Refresh token in grace period and revoke the old one.
     */
    public String refreshInGracePeriodWithRevoke(String token, JwtProperties properties) {
        if (!key.isValidWithGraceful(token)) return null;
        String newToken;
        try {
            newToken = key.generateToken(properties);
        } catch (Exception e) {
            return null;
        }
        if (newToken != null) revokeToken(token);
        return newToken;
    }

    public <T> String refreshInGracePeriodWithRevoke(String token, JwtProperties properties, T claims, Class<T> clazz) {
        if (!key.isValidWithGraceful(token)) return null;
        String newToken;
        try {
            newToken = key.generateToken(properties, claims, clazz);
        } catch (Exception e) {
            return null;
        }
        if (newToken != null) revokeToken(token);
        return newToken;
    }

    /**
     * Revoke a token by adding it to the blacklist (revocation store).
     */
    public boolean revokeToken(String token) {
        if (revocationStore == null) return false;
        String fingerprint = fingerprintToken(token);
        Date expiry = key.decodeExpiration(token);
        if (expiry == null) return false;
        revocationStore.revoke(fingerprint, expiry.getTime());
        return true;
    }

    /**
     * Check if a token has been revoked.
     */
    public boolean isRevoked(String token) {
        if (revocationStore == null) return false;
        String fingerprint = fingerprintToken(token);
        boolean revoked = revocationStore.isRevoked(fingerprint);
        if (revoked) key.recordBlacklistHit();
        return revoked;
    }

    /**
     * Check if token is within the "advance" window before expiration.
     */
    private boolean isNearExpiry(String token, long advanceMs) {
        Date expiry = key.decodeExpiration(token);
        if (expiry == null) return false;

        Instant refreshDeadline = expiry.toInstant().minusMillis(advanceMs);
        return !Instant.now().isBefore(refreshDeadline);
    }

    private boolean canRefreshNearExpiry(String token, long advanceMs) {
        if (!key.isTokenDecodable(token)) return false;
        if (isRevoked(token)) return false;
        Date expiry = key.decodeExpiration(token);
        if (expiry == null) return false;
        Instant refreshDeadline = expiry.toInstant().minusMillis(advanceMs);
        return !Instant.now().isBefore(refreshDeadline);
    }

    private String fingerprintToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return Integer.toString(token.hashCode());
        }
    }
}
