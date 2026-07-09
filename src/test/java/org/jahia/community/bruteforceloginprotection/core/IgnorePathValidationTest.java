package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SettingsService#validateIgnorePaths(java.util.List)}. The method is
 * package-private static, so it is exercised directly. No OSGi/JCR/ConfigurationAdmin needed.
 */
public class IgnorePathValidationTest {

    @Test
    public void nullOrEmptyList_accepted() {
        assertThatCode(() -> SettingsService.validateIgnorePaths(null)).doesNotThrowAnyException();
        assertThatCode(() -> SettingsService.validateIgnorePaths(Collections.emptyList()))
                .doesNotThrowAnyException();
    }

    @Test
    public void ordinaryUriSubstrings_accepted() {
        assertThatCode(() -> SettingsService.validateIgnorePaths(
                Arrays.asList("modules-repository.moduleList.json", "/health", "/actuator/metrics")))
                .doesNotThrowAnyException();
    }

    @Test
    public void blankEntries_accepted() {
        // joinList drops these; they are harmless.
        assertThatCode(() -> SettingsService.validateIgnorePaths(Arrays.asList("", "   ")))
                .doesNotThrowAnyException();
    }

    @Test
    public void crlfEntry_rejected() {
        // Build the CR/LF at runtime so no control byte ever appears in this source file.
        String injected = "/store" + (char) 0x0D + (char) 0x0A + "Injected: header";
        assertThatThrownBy(() -> SettingsService.validateIgnorePaths(Collections.singletonList(injected)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("control characters");
    }

    @Test
    public void controlCharEntry_rejected() {
        // 0x07 (BEL) constructed at runtime — keeps the source file free of raw control bytes.
        String withBell = "/store" + (char) 0x07 + "x";
        assertThatThrownBy(() -> SettingsService.validateIgnorePaths(Collections.singletonList(withBell)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("control characters");
    }

    @Test
    public void overLongEntry_rejected() {
        String tooLong = "/" + "a".repeat(512);
        assertThatThrownBy(() -> SettingsService.validateIgnorePaths(Collections.singletonList(tooLong)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("512");
    }

    @Test
    public void maxLengthEntry_accepted() {
        String exactly512 = "a".repeat(512);
        assertThatCode(() -> SettingsService.validateIgnorePaths(Collections.singletonList(exactly512)))
                .doesNotThrowAnyException();
    }
}
