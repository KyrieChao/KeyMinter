package com.chao.keyminter.domain.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 密钥状态枚举
 * 支持密钥生命周期管理，包括重叠期（transition period）
 */
@Getter
@RequiredArgsConstructor
public enum KeyStatus {

    /**
     * 密钥刚创建，尚未激活
     * 可以用于预生成密钥，等待激活
     */
    CREATED("created", "密钥已创建，等待激活"),

    /**
     * 密钥处于激活状态，是主要的签名密钥
     */
    ACTIVE("active", "密钥已激活，正在使用"),

    /**
     * 密钥处于过渡期（重叠期）
     * 新密钥已激活，但旧密钥仍可验证
     */
    TRANSITIONING("transitioning", "密钥处于过渡期，新旧密钥同时有效"),

    /**
     * 密钥已停用，不再用于签名，但仍可验证现有Token
     */
    INACTIVE("inactive", "密钥已停用，仅用于验证"),

    /**
     * 密钥已过期，完全不可用
     */
    EXPIRED("expired", "密钥已过期"),

    /**
     * 密钥被手动撤销
     */
    REVOKED("revoked", "密钥已被撤销");

    private final String code;
    private final String description;

    /**
     * 检查密钥是否可用于签名
     */
    public boolean canSign() {
        return this == ACTIVE || this == TRANSITIONING;
    }

    /**
     * 检查密钥是否可用于验证
     */
    public boolean canVerify() {
        return this == ACTIVE || this == TRANSITIONING || this == INACTIVE;
    }

    /**
     * 检查密钥是否处于活跃状态（包括在过渡期）
     */
    public boolean isActiveOrTransitioning() {
        return this == ACTIVE || this == TRANSITIONING;
    }

    /**
     * 检查密钥是否已完全失效
     */
    public boolean isExpiredOrRevoked() {
        return this == EXPIRED || this == REVOKED;
    }
}
