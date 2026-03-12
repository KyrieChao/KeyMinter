package com.chao.keyMinter.domain.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Key Status Enumeration
 * Supports key lifecycle management, including transition period.
 */
@Getter
@RequiredArgsConstructor
public enum KeyStatus {

    /**
     * Key is created but not yet activated.
     * Can be used for pre-generation, waiting for activation.
     */
    CREATED("created", "Key is created, waiting for activation"),

    /**
     * Key is active and is the primary signing key.
     */
    ACTIVE("active", "Key is active and in use"),

    /**
     * Key is in transition period (overlap period).
     * New key is active, but old key is still valid for verification.
     */
    TRANSITIONING("transitioning", "Key is in transition, both new and old keys are valid"),

    /**
     * Key is inactive, no longer used for signing, but still valid for verification of existing tokens.
     */
    INACTIVE("inactive", "Key is inactive, only for verification"),

    /**
     * Key is expired, completely unusable.
     */
    EXPIRED("expired", "Key is expired"),

    /**
     * Key is manually revoked.
     */
    REVOKED("revoked", "Key is revoked");

    private final String code;
    private final String description;

    /**
     * Check if key can be used for signing.
     */
    public boolean canSign() {
        return this == ACTIVE || this == TRANSITIONING;
    }

    /**
     * Check if key can be used for verification.
     */
    public boolean canVerify() {
        return this == ACTIVE || this == TRANSITIONING || this == INACTIVE;
    }

    /**
     * Check if key is in active state (including transition).
     */
    public boolean isActiveOrTransitioning() {
        return this == ACTIVE || this == TRANSITIONING;
    }

    /**
     * Check if key is completely invalid.
     */
    public boolean isExpiredOrRevoked() {
        return this == EXPIRED || this == REVOKED;
    }
}
