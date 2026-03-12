package com.chao.keyminter.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * 密钥版本信息
 * 包含密钥的完整生命周期信息
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyVersion {

    /**
     * 密钥ID
     */
    private String keyId;

    /**
     * 算法类型
     */
    private Algorithm algorithm;

    /**
     * 密钥状态
     */
    @Builder.Default
    private KeyStatus status = KeyStatus.CREATED;

    /**
     * 密钥文件路径
     */
    private String keyPath;

    /**
     * 创建时间
     */
    private LocalDateTime createdTime;

    /**
     * 激活时间
     */
    private LocalDateTime activatedTime;

    /**
     * 过期时间（绝对时间）
     */
    private Instant expiresAt;

    /**
     * 过渡期结束时间
     * 在轮换时设置，旧密钥在过渡期内仍可验证
     */
    private Instant transitionEndsAt;

    /**
     * 停用时间
     */
    private LocalDateTime deactivatedTime;

    /**
     * 是否活跃（兼容旧版本，推荐使用status字段）
     *
     * @deprecated 使用 {@link #getStatus()} 替代
     */
    @Deprecated
    private Boolean active;

    public KeyVersion(String keyId, Algorithm algorithm, String keyPath) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keyPath = keyPath;
    }

    /**
     * 获取当前状态
     * 会自动检查是否已过期
     */
    public KeyStatus getStatus() {
        // 如果已过期但状态未更新，自动更新状态
        if (status != KeyStatus.EXPIRED && status != KeyStatus.REVOKED) {
            if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
                return KeyStatus.EXPIRED;
            }
        }
        return status;
    }

    /**
     * 检查密钥是否可用于签名
     */
    public boolean canSign() {
        return getStatus().canSign();
    }

    /**
     * 检查密钥是否可用于验证
     */
    public boolean canVerify() {
        KeyStatus currentStatus = getStatus();
        if (!currentStatus.canVerify()) {
            return false;
        }
        // 检查过渡期
        if (currentStatus == KeyStatus.INACTIVE && transitionEndsAt != null) {
            return Instant.now().isBefore(transitionEndsAt);
        }
        return true;
    }

    /**
     * 检查密钥是否在过渡期内
     */
    public boolean isInTransitionPeriod() {
        return status == KeyStatus.TRANSITIONING ||
                (status == KeyStatus.INACTIVE && transitionEndsAt != null && Instant.now().isBefore(transitionEndsAt));
    }

    /**
     * 检查密钥是否已过期
     */
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * 获取剩余有效时间（秒）
     */
    public long getRemainingSeconds() {
        if (expiresAt == null) {
            return Long.MAX_VALUE;
        }
        long remaining = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(0, remaining);
    }

    /**
     * 激活密钥
     */
    public void activate() {
        this.status = KeyStatus.ACTIVE;
        this.activatedTime = LocalDateTime.now();
    }

    /**
     * 开始过渡期
     */
    public void startTransition(Instant transitionEndTime) {
        this.status = KeyStatus.TRANSITIONING;
        this.transitionEndsAt = transitionEndTime;
    }

    /**
     * 停用密钥
     */
    public void deactivate() {
        this.status = KeyStatus.INACTIVE;
        this.deactivatedTime = LocalDateTime.now();
    }

    /**
     * 标记为过期
     */
    public void markExpired() {
        this.status = KeyStatus.EXPIRED;
    }

    /**
     * 撤销密钥
     */
    public void revoke() {
        this.status = KeyStatus.REVOKED;
    }

    /**
     * 设置过期时间
     */
    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
        // 如果已过期，自动更新状态
        if (expiresAt != null && Instant.now().isAfter(expiresAt)) {
            this.status = KeyStatus.EXPIRED;
        }
    }
}
