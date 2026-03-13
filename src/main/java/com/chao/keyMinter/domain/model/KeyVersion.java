package com.chao.keyMinter.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * Key Version Model.
 * Represents a specific version of a key with its metadata and status.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyVersion {

    /**
     * Key ID.
     */
    private String keyId;

    /**
     * Algorithm used by this key.
     */
    private Algorithm algorithm;

    /**
     * Current status of the key.
     */
    @Builder.Default
    private KeyStatus status = KeyStatus.CREATED;

    /**
     * Path to the key file.
     */
    private String keyPath;

    /**
     * Creation timestamp.
     */
    private LocalDateTime createdTime;

    /**
     * Activation timestamp.
     */
    private LocalDateTime activatedTime;

    /**
     * Expiration timestamp.
     * When this time is reached, the key status becomes EXPIRED (unless it is already REVOKED).
     */
    private Instant expiresAt;

    /**
     * Transition end timestamp.
     * Used for graceful rotation. When a key is INACTIVE, it might still be valid for verification until this time.
     */
    private Instant transitionEndsAt;

    /**
     * Deactivation timestamp.
     */
    private LocalDateTime deactivatedTime;


    public KeyVersion(String keyId, Algorithm algorithm, String keyPath) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keyPath = keyPath;
    }

    /**
     * Get the current status, calculating dynamic states like EXPIRED.
     */
    public KeyStatus getStatus() {
        // Check for expiration dynamically if not already expired or revoked
        if (status != KeyStatus.EXPIRED && status != KeyStatus.REVOKED) {
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                return KeyStatus.EXPIRED;
            }
        }
        return status;
    }

    /**
     * Check if the key can be used for signing.
     */
    public boolean canSign() {
        return getStatus().canSign();
    }

    /**
     * Check if the key can be used for verification.
     */
    public boolean canVerify() {
        KeyStatus currentStatus = getStatus();
        if (!currentStatus.canVerify()) {
            return false;
        }
        // Check transition period for inactive keys
        if (currentStatus == KeyStatus.INACTIVE && transitionEndsAt != null) {
            return Instant.now().isBefore(transitionEndsAt);
        }
        return true;
    }

    /**
     * Check if the key is in the transition period (grace period).
     */
    public boolean isInTransitionPeriod() {
        return status == KeyStatus.TRANSITIONING ||
                (status == KeyStatus.INACTIVE && transitionEndsAt != null && Instant.now().isBefore(transitionEndsAt));
    }


    /**
     * Check if the key is expired.
     */
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Get the remaining validity time in seconds.
     */
    public long getRemainingSeconds() {
        if (expiresAt == null) {
            return Long.MAX_VALUE;
        }
        long remaining = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(0, remaining);
    }

    /**
     * Activate the key.
     */
    public void activate() {
        this.status = KeyStatus.ACTIVE;
        this.activatedTime = LocalDateTime.now();
    }

    /**
     * Start the transition period (graceful rotation).
     */
    public void startTransition(Instant transitionEndTime) {
        this.status = KeyStatus.TRANSITIONING;
        this.transitionEndsAt = transitionEndTime;
    }

    /**
     * Deactivate the key.
     */
    public void deactivate() {
        this.status = KeyStatus.INACTIVE;
        this.deactivatedTime = LocalDateTime.now();
    }

    /**
     * Mark the key as expired.
     */
    public void markExpired() {
        this.status = KeyStatus.EXPIRED;
    }

    /**
     * Revoke the key.
     */
    public void revoke() {
        this.status = KeyStatus.REVOKED;
    }

    /**
     * Set the expiration time.
     */
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
        // Update status immediately if already expired
        if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
            this.status = KeyStatus.EXPIRED;
        }
    }
}
