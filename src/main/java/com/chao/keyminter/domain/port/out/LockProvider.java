package com.chao.keyminter.domain.port.out;

import java.util.concurrent.locks.Lock;

/**
 * 分布式锁提供者接口
 */
public interface LockProvider {
    /**
     * 获取锁
     * @param key 锁的键（通常是密钥目录路径或ID）
     * @return 锁对象（类似于 java.util.concurrent.locks.Lock）
     */
    Lock getLock(String key);
}
