package com.chao.keyminter.adapter.in.spring;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.adapter.out.fs.FileSystemKeyRepositoryFactory;
import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.core.KeyRotation;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyminter.domain.port.out.LockProvider;
import com.chao.keyminter.adapter.out.redis.RedisLockProvider;
import com.chao.keyminter.domain.port.out.RevocationStore;
import com.chao.keyminter.adapter.out.redis.RedisRevocationStore;
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

    // 这里预留 Redis KeyRepository 的扩展点
    // @Bean
    // @ConditionalOnProperty(prefix = "key-minter.repository", name = "type", havingValue = "redis")
    // public KeyRepositoryFactory redisKeyRepositoryFactory(...) { ... }

    @Bean
    @ConditionalOnMissingBean(JwtFactory.class)
    public JwtFactory jwtFactory(KeyMinterProperties properties, KeyRepositoryFactory repoFactory) {
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
        // 静态注入到工具类（因为 AtomicKeyRotation 目前是工具类设计）
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
