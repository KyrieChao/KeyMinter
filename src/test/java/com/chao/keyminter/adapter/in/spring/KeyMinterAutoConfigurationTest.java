package com.chao.keyminter.adapter.in.spring;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.core.JwtFactory;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class KeyMinterAutoConfigurationTest {

    @Test
    void testBeanCreation() {
        KeyMinterAutoConfiguration config = new KeyMinterAutoConfiguration();

        KeyMinterProperties props = new KeyMinterProperties();
        KeyRepositoryFactory repoFactory = Mockito.mock(KeyRepositoryFactory.class);

        JwtFactory jwtFactory = config.jwtFactory(props, repoFactory);
        assertNotNull(jwtFactory);

        KeyMinter keyMinter = config.keyMinterBean(jwtFactory);
        assertNotNull(keyMinter);
    }
}
