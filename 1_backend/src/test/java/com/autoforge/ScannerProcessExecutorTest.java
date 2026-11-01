package com.autoforge;

import com.autoforge.service.ScannerProcessExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScannerProcessExecutorTest {
    @TempDir
    Path tempDirectory;

    @Test
    void startsProcessWithoutShellAndCapturesOutput() throws Exception {
        String javaExecutable = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase().contains("win") ? "java.exe" : "java").toString();

        ScannerProcessExecutor.ProcessResult result = new ScannerProcessExecutor().execute(
                List.of(javaExecutable, "-version"), tempDirectory, Duration.ofSeconds(10));

        assertTrue(result.finished());
        assertEquals(0, result.exitCode());
        assertTrue(result.output().contains("version"));
    }
}
