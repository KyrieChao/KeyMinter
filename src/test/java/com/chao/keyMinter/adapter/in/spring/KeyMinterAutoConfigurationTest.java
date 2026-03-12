package com.chao.keyMinter.adapter.in.spring;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.adapter.out.fs.FileSystemKeyRepositoryFactory;
import com.chao.keyMinter.adapter.out.redis.RedisLockProvider;
import com.chao.keyMinter.adapter.out.redis.RedisRevocationStore;
import com.chao.keyMinter.api.KeyMinter;
import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.core.KeyRotation;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.LockProvider;
import com.chao.keyMinter.domain.port.out.RevocationStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class KeyMinterAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(KeyMinterAutoConfiguration.class));

    @AfterEach
    void tearDown() {
        // Ensure static state is cleared to prevent pollution of other tests
        KeyRotation.setLockProvider(null);
    }

    @Test
    void testDefaultConfiguration() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(KeyMinterProperties.class);
            assertThat(context).hasSingleBean(FileSystemKeyRepositoryFactory.class);
            assertThat(context).hasSingleBean(JwtFactory.class);
            assertThat(context).hasSingleBean(KeyMinter.class);
            
            // Default: Redis disabled
            assertThat(context).doesNotHaveBean(LockProvider.class);
            assertThat(context).doesNotHaveBean(RevocationStore.class);
        });
    }

    @Test
    void testRedisLockEnabled() {
        contextRunner
                .withPropertyValues("key-minter.lock.redis-enabled=true")
                .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(LockProvider.class);
                    assertThat(context).hasSingleBean(RedisLockProvider.class);
                });
    }

    @Test
    void testRedisBlacklistEnabled() {
        contextRunner
                .withPropertyValues("key-minter.blacklist.redis-enabled=true")
                .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(RevocationStore.class);
                    assertThat(context).hasSingleBean(RedisRevocationStore.class);
                });
    }

    @Test
    void testCustomKeyRepository() {
        contextRunner
                .withBean(KeyRepositoryFactory.class, () -> mock(KeyRepositoryFactory.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyRepositoryFactory.class);
                    assertThat(context).doesNotHaveBean(FileSystemKeyRepositoryFactory.class);
                });
    }

    @Test
    void testCustomJwtFactory() {
        contextRunner
                .withBean(JwtFactory.class, () -> new JwtFactory())
                .run(context -> {
                    assertThat(context).hasSingleBean(JwtFactory.class);
                    // The auto-configured one should be backed off
                });
    }

    @Test
    void testCustomKeyMinter() {
        contextRunner
                .withBean(KeyMinter.class, () -> mock(KeyMinter.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyMinter.class);
                    // The auto-configured one should be backed off
                });
    }

    @Test
    void testJwtFactoryWithNullProperties() {
        // Direct method call to test the null check branch
        KeyMinterAutoConfiguration config = new KeyMinterAutoConfiguration();
        KeyRepositoryFactory repoFactory = mock(KeyRepositoryFactory.class);
        
        // Should print error to stderr but not throw exception
        JwtFactory factory = config.jwtFactory(null, repoFactory);
        
        assertThat(factory).isNotNull();
    }
    
    @Test
    void testJwtFactoryWithProperties() {
        // Direct method call to test the normal branch with System.out
        KeyMinterAutoConfiguration config = new KeyMinterAutoConfiguration();
        KeyRepositoryFactory repoFactory = mock(KeyRepositoryFactory.class);
        KeyMinterProperties properties = new KeyMinterProperties();
        
        JwtFactory factory = config.jwtFactory(properties, repoFactory);
        
        assertThat(factory).isNotNull();
    }
}


