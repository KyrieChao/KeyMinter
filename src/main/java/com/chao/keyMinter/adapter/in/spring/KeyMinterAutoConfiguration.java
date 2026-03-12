package com.chao.keyMinter.adapter.in.spring;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.adapter.out.fs.FileSystemKeyRepositoryFactory;
import com.chao.keyMinter.api.KeyMinter;
import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.core.KeyRotation;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.LockProvider;
import com.chao.keyMinter.adapter.out.redis.RedisLockProvider;
import com.chao.keyMinter.domain.port.out.RevocationStore;
import com.chao.keyMinter.adapter.out.redis.RedisRevocationStore;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;

@AutoConfiguration
@EnableConfigurationProperties({KeyMinterProperties.class})
@ConditionalOnClass({JwtFactory.class, Algorithm.class})
@EnableScheduling
public class KeyMinterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(KeyRepositoryFactory.class)
    @ConditionalOnProperty(prefix = "key-minter.repository", name = "type", havingValue = "filesystem", matchIfMissing = true)
    public KeyRepositoryFactory fileSystemKeyRepositoryFactory() {
        return new FileSystemKeyRepositoryFactory();
    }

    // Redis KeyRepository factory can be added here
    // @Bean
    // @ConditionalOnProperty(prefix = "key-minter.repository", name = "type", havingValue = "redis")
    // public KeyRepositoryFactory redisKeyRepositoryFactory(...) { ... }

    @Bean
    @ConditionalOnMissingBean(JwtFactory.class)
    public JwtFactory jwtFactory(KeyMinterProperties properties, KeyRepositoryFactory repoFactory) {
        if (properties == null) {
            System.err.println("KeyMinterAutoConfiguration: properties injected is NULL!");
        } else {
            System.out.println("KeyMinterAutoConfiguration: properties injected: " + properties + ", KeyDir: " + properties.getKeyDir());
        }
        JwtFactory factory = new JwtFactory();
        factory.setProperties(properties);
        factory.setRepositoryFactory(repoFactory);
        return factory;
    }

    @Bean
    @ConditionalOnMissingBean(KeyMinter.class)
    public KeyMinter keyMinterBean(JwtFactory jwtFactory) {
        return new KeyMinter(jwtFactory);
    }

    @Bean
    @ConditionalOnProperty(prefix = "key-minter.lock", name = "redis-enabled", havingValue = "true")
    @ConditionalOnMissingBean(LockProvider.class)
    @ConditionalOnClass(StringRedisTemplate.class)
    public LockProvider redisLockProvider(StringRedisTemplate redisTemplate, KeyMinterProperties properties) {
        KeyMinterProperties.Lock lockProps = properties.getLock();
        RedisLockProvider provider = new RedisLockProvider(
                redisTemplate,
                lockProps.getRedisKeyPrefix(),
                lockProps.getExpireMillis(),
                lockProps.getRetryIntervalMillis(),
                lockProps.getMaxRetryIntervalMillis()
        );
        // Set lock provider for AtomicKeyRotation
        KeyRotation.setLockProvider(provider);
        return provider;
    }

    @Bean
    @ConditionalOnProperty(prefix = "key-minter.blacklist", name = "redis-enabled", havingValue = "true")
    @ConditionalOnMissingBean(RevocationStore.class)
    @ConditionalOnClass(StringRedisTemplate.class)
    public RevocationStore redisRevocationStore(StringRedisTemplate redisTemplate, KeyMinterProperties properties) {
        return new RedisRevocationStore(redisTemplate, properties.getBlacklist().getRedisKeyPrefix());
    }
}
