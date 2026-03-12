package com.chao.keyminter.api;

import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.port.out.RevocationStore;
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
     * 刷新Token（宽限期内无条件刷新，不撤销旧Token）
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
     * 刷新Token（临过期才允许刷新，不撤销旧Token）
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
     * 刷新Token（临过期才允许刷新，并撤销旧Token防重放）
     */
    public String refreshNearExpiryWithRevoke(String token, JwtProperties properties, long advanceMs) {
        if (!isNearExpiry(token, advanceMs) || !key.isTokenDecodable(token)) return null;
        // 生成新token
        String newToken;
        try {
            newToken = key.generateToken(properties);
        } catch (Exception e) {
            return null;
        }
        // 生成成功后再撤销旧token
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
     * 刷新Token（宽限期内，并撤销旧Token防重放）
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
     * 撤销Token（加入黑名单）
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
     * 检查Token是否已撤销
     */
    public boolean isRevoked(String token) {
        if (revocationStore == null) return false;
        String fingerprint = fingerprintToken(token);
        boolean revoked = revocationStore.isRevoked(fingerprint);
        if (revoked) key.recordBlacklistHit();
        return revoked;
    }

    /**
     * 检查是否临过期（不查黑名单，避免重复计算）
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