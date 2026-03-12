package com.chao.keyMinter.domain.port.out;

import org.springframework.stereotype.Component;

/**
 * Revocation Store Interface.
 * Abstraction for revocation checks (Redis, Bloom Filter, etc.).
 */
@Component
public interface RevocationStore {

    /** 
     * Revoke a fingerprint until a specific time.
     * @param fingerprint The fingerprint to revoke.
     * @param until Timestamp until which the revocation is valid.
     */
    void revoke(String fingerprint, long until);

    /** 
     * Check if a fingerprint is revoked.
     * @param fingerprint The fingerprint to check.
     * @return True if revoked, false otherwise.
     */
    boolean isRevoked(String fingerprint);

    /** 
     * Preload revocation data if needed (e.g. from database to memory).
     */
    default void preload() {}
}
