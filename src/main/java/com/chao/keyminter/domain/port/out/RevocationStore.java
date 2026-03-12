package com.chao.keyminter.domain.port.out;

import org.springframework.stereotype.Component;

/**
 * 撤销存储抽象，内存/Redis/Bloom 都可插拔
 */
@Component
public interface RevocationStore {

    /** 撤销 token，until=过期时间戳（毫秒） */
    void revoke(String fingerprint, long until);

    /** 是否已撤销（未过期返回 true） */
    boolean isRevoked(String fingerprint);

    /** 启动时异步预热（可选） */
    default void preload() {}
}