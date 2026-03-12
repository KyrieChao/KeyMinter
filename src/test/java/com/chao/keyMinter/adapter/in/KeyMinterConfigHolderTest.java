package com.chao.keyMinter.adapter.in;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyMinterConfigHolderTest {

    @AfterEach
    void tearDown() throws Exception {
        // Reset the static field to avoid side effects on other tests
        Field field = KeyMinterConfigHolder.class.getDeclaredField("ctx");
        field.setAccessible(true);
        field.set(null, null);
    }

    @Test
    void testSetApplicationContextNull() {
        KeyMinterConfigHolder holder = new KeyMinterConfigHolder();
        assertThrows(NullPointerException.class, () -> holder.setApplicationContext(null));
    }

    @Test
    void testSetApplicationContextAndGet() {
        // Arrange
        ApplicationContext mockContext = mock(ApplicationContext.class);
        KeyMinterProperties mockProperties = new KeyMinterProperties();
        when(mockContext.getBean(KeyMinterProperties.class)).thenReturn(mockProperties);

        KeyMinterConfigHolder holder = new KeyMinterConfigHolder();

        // Act
        holder.setApplicationContext(mockContext);
        KeyMinterProperties result = KeyMinterConfigHolder.get();

        // Assert
        assertNotNull(result);
        assertEquals(mockProperties, result);
    }

    @Test
    void testGetWithNullContext() {
        // Arrange
        // Ensure context is null (it should be due to tearDown, but let's be safe)

        // Act
        KeyMinterProperties result = KeyMinterConfigHolder.get();

        // Assert
        assertNotNull(result);
        // Should return a new instance with default values
        assertNotNull(result.getKeyDir());
    }
}
