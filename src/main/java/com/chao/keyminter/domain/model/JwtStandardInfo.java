package com.chao.keyminter.domain.model;

import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Data
@Builder
public class JwtStandardInfo {
    private String subject;
    private String issuer;
    private Date issuedAt;
    private Date expiration;
    
    // 便捷方法：获取剩余有效时间（毫秒）
    public long getRemainingTime() {
        if (expiration == null) return 0;
        return expiration.getTime() - System.currentTimeMillis();
    }
    
    // 便捷方法：检查是否已过期
    public boolean isExpired() {
        return getRemainingTime() <= 0;
    }
}
