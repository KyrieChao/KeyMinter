package com.chao.keyMinter.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtProperties {
    private String subject;
    private String issuer;
    private Instant expiration;
}
