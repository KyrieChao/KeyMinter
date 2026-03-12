package com.chao.keyMinter.domain.model;

import lombok.Data;

import java.util.Map;

@Data
public class JwtFullInfo<T> {
    private JwtStandardInfo standardInfo;
    private T customClaims;
    private Map<String, Object> allClaims;

    public Object getCustomClaim(String key) {
        return allClaims != null ? allClaims.get(key) : null;
    }

    public boolean hasClaim(String key) {
        return allClaims != null && allClaims.containsKey(key);
    }
}



