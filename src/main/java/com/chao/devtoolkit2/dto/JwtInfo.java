package com.chao.devtoolkit.dto;

import com.chao.devtoolkit.config.JwtProperties;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtInfo {
    private String subject;
    private String issuer;
    private Long expiration;

    public JwtProperties toProperties() {
        return JwtProperties.builder()
                .subject(this.subject)
                .issuer(this.issuer)
                .expiration(this.expiration)
                .build();
    }
}
