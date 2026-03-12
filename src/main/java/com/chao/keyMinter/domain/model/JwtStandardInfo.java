package com.chao.keyMinter.domain.model;

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
    
    // Get remaining validity time in milliseconds
    public long getRemainingTime() {
        if (expiration == null) return 0;
        return expiration.getTime() - System.currentTimeMillis();
    }
    
    // Check if the token is expired
    public boolean isExpired() {
        return getRemainingTime() <= 0;
    }
}
