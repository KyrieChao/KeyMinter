package com.chao.keyMinter.internal;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RevocationStoreTest {

    @Test
    void revokeJti_should_ignore_null_or_empty() {
        // Arrange
        RevocationStore store = new RevocationStore();

        // Act
        store.revokeJti(null);
        store.revokeJti("");

        // Assert
        assertEquals(Set.of(), store.getRevokedJtis());
        store.close();
    }

    @Test
    void revokeJti_and_isRevokedJti_should_handle_active_and_expired_entries() {
        // Arrange
        RevocationStore store = new RevocationStore();
        String active = "a";
        String expired = "e";

        // Act
        store.revokeJti(active);
        store.revokeJti(expired, Instant.now().minusSeconds(1));

        // Assert
        assertTrue(store.isRevokedJti(active));
        assertFalse(store.isRevokedJti(expired));
        assertFalse(store.getRevokedJtis().contains(expired));
        store.close();
    }

    @Test
    void revokeFingerprint_and_isRevokedFingerprint_should_handle_active_and_expired_entries() {
        // Arrange
        RevocationStore store = new RevocationStore();
        String active = "fp-a";
        String expired = "fp-e";

        // Act
        store.revokeFingerprint(active);
        store.revokeFingerprint(expired, Instant.now().minusSeconds(1));

        // Assert
        assertTrue(store.isRevokedFingerprint(active));
        assertFalse(store.isRevokedFingerprint(expired));
        assertFalse(store.getRevokedFingerprints().contains(expired));
        store.close();
    }

    @Test
    void cleanupExpiredEntries_should_remove_expired_and_keep_valid() {
        // Arrange
        RevocationStore store = new RevocationStore();
        store.revokeJti("valid-jti", Instant.now().plusSeconds(60));
        store.revokeJti("expired-jti", Instant.now().minusSeconds(1));
        store.revokeFingerprint("valid-fp", Instant.now().plusSeconds(60));
        store.revokeFingerprint("expired-fp", Instant.now().minusSeconds(1));

        // Act
        store.cleanupExpiredEntries();

        // Assert
        assertTrue(store.isRevokedJti("valid-jti"));
        assertFalse(store.isRevokedJti("expired-jti"));
        assertTrue(store.isRevokedFingerprint("valid-fp"));
        assertFalse(store.isRevokedFingerprint("expired-fp"));
        store.close();
    }

    @Test
    void getStats_and_clear_should_reflect_current_state() {
        // Arrange
        RevocationStore store = new RevocationStore();
        store.revokeJti("j1");
        store.revokeFingerprint("f1");

        // Act
        Map<String, Integer> stats = store.getStats();
        store.clear();
        Map<String, Integer> afterClear = store.getStats();

        // Assert
        assertEquals(1, stats.get("revokedJtis"));
        assertEquals(1, stats.get("revokedFingerprints"));
        assertEquals(0, afterClear.get("revokedJtis"));
        assertEquals(0, afterClear.get("revokedFingerprints"));
        store.close();
    }

    @Test
    void close_should_shutdown_scheduler_and_be_idempotent() throws Exception {
        // Arrange
        RevocationStore store = new RevocationStore(new KeyMinterProperties());

        ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
        when(scheduler.awaitTermination(anyLong(), any(TimeUnit.class))).thenReturn(true);
        injectScheduler(store, scheduler);

        // Act
        store.close();
        store.close();

        // Assert
        verify(scheduler, times(1)).shutdown();
        verify(scheduler, times(1)).awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    void close_should_call_shutdownNow_when_not_terminated() throws Exception {
        // Arrange
        RevocationStore store = new RevocationStore(new KeyMinterProperties());

        ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
        when(scheduler.awaitTermination(anyLong(), any(TimeUnit.class))).thenReturn(false);
        injectScheduler(store, scheduler);

        // Act
        store.close();

        // Assert
        verify(scheduler).shutdown();
        verify(scheduler).shutdownNow();
    }

    @Test
    void close_should_handle_interrupted_exception() throws Exception {
        // Arrange
        RevocationStore store = new RevocationStore(new KeyMinterProperties());

        ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
        when(scheduler.awaitTermination(anyLong(), any(TimeUnit.class))).thenThrow(new InterruptedException("x"));
        injectScheduler(store, scheduler);

        // Act
        store.close();

        // Assert
        verify(scheduler).shutdown();
        verify(scheduler).shutdownNow();
        assertTrue(Thread.currentThread().isInterrupted());
        Thread.interrupted();
    }

    @Test
    void finalize_should_close_store() throws Exception {
        // Arrange
        RevocationStore store = new RevocationStore(new KeyMinterProperties());
        ScheduledExecutorService scheduler = Mockito.mock(ScheduledExecutorService.class);
        when(scheduler.awaitTermination(anyLong(), any(TimeUnit.class))).thenReturn(true);
        injectScheduler(store, scheduler);

        // Act
        java.lang.reflect.Method finalizeMethod = RevocationStore.class.getDeclaredMethod("finalize");
        finalizeMethod.setAccessible(true);
        finalizeMethod.invoke(store);

        // Assert
        verify(scheduler).shutdown();
    }

    private static void injectScheduler(RevocationStore store, ScheduledExecutorService scheduler) throws Exception {
        Field f = RevocationStore.class.getDeclaredField("cleanupScheduler");
        f.setAccessible(true);
        f.set(store, scheduler);
    }
}

