package com.chao.keyMinter.adapter.in.spring;

import com.chao.keyMinter.api.KeyMinter;
import jakarta.annotation.Resource;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * KeyMinter Health Indicator
 * Exposed for Spring Boot Actuator
 */
@Component("keyMinterHealthIndicator")
public class KeyMinterHealthIndicator implements HealthIndicator {

    @Resource
    private KeyMinter keyMinter;

    @Override
    public Health health() {
        try {
            boolean exists = keyMinter.keyPairExists();
            String activeKeyId = keyMinter.getActiveKeyId();
            Path keyPath = keyMinter.getKeyPath();
            
            // Simple readability check
            boolean dirReadable = keyPath != null && Files.exists(keyPath) && Files.isDirectory(keyPath) && Files.isReadable(keyPath);
            
            int cacheSize = keyMinter.getCacheSize();
            String algoInfo = keyMinter.getAlgorithmInfo();

            Health.Builder builder = exists ? Health.up() : Health.down();
            builder.withDetail("activeKeyId", activeKeyId != null ? activeKeyId : "none")
                    .withDetail("keyDir", keyPath != null ? keyPath.toString() : "null")
                    .withDetail("dirReadable", dirReadable)
                    .withDetail("cacheSize", cacheSize)
                    .withDetail("algorithm", algoInfo != null ? algoInfo : "unknown");
            
            return builder.build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
