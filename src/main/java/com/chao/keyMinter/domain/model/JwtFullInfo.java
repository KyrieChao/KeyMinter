package com.chao.keyMinter.domain.model;

import lombok.Data;

import java.util.Map;

/**
 * JwtFullInfo 类是一个泛型类，用于存储JWT令牌的完整信息
 * 包含标准信息、自定义声明和所有声明的映射
 */
@Data
public class JwtFullInfo<T> {
    /**
     * JwtStandardInfo 类型的对象，存储JWT令牌的标准信息
     * 通常包括iss(签发者)、sub(主题)、aud(接收方)、exp(过期时间)等标准声明
     */
    private JwtStandardInfo standardInfo;
    /**
     * 泛型类型T的对象，用于存储自定义的声明信息
     * 允许用户根据需要添加自定义的JWT声明
     */
    private T customClaims;
    /**
     * Map类型的对象，存储所有的声明信息
     * 键为声明名称(String类型)，值为声明内容(Object类型)
     * 包含标准声明和自定义声明
     */
    private Map<String, Object> allClaims;

    /**
     * 根据指定的键获取自定义声明值
     * 这是一个从allClaims映射中获取值的方法
     *
     * @param key 自定义声明的键名
     * @return 返回键对应的值，如果allClaims为null则返回null
     */
    public Object getCustomClaim(String key) {
        return allClaims != null ? allClaims.get(key) : null;
    }

    /**
     * 检查是否包含指定的声明键
     * 用于验证某个声明是否存在
     *
     * @param key 要检查的声明键
     * @return 如果存在该键返回true，否则返回false
     */
    public boolean hasClaim(String key) {
        return allClaims != null && allClaims.containsKey(key);
    }
}



