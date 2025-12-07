package com.chao.devtoolkit.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JwtProperties {
    private String subject;
    private String issuer;
    private Long expiration;
}
