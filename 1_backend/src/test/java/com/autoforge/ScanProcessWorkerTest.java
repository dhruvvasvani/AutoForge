package com.autoforge;

import com.autoforge.service.ScanProcessWorker;
import com.autoforge.service.ScanService;
import com.autoforge.service.ScanSourceStorageService;
import com.autoforge.service.ScannerProcessExecutor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class ScanProcessWorkerTest {
    @TempDir
    Path tempDirectory;

    @Test
    void invokesConfiguredWrapperWithSourceAndOutputArguments() throws Exception {
        Path uploadRoot = Files.createDirectory(tempDirectory.resolve("uploads"));
        Path source = Files.createDirectory(uploadRoot.resolve("source"));
        Path wrapper = Files.writeString(tempDirectory.resolve("scan_wrapper.py"), "print('scanner')");
        ScanService scanService = mock(ScanService.class);
        ScannerProcessExecutor executor = mock(ScannerProcessExecutor.class);
        ScanSourceStorageService storage = new ScanSourceStorageService(uploadRoot.toString(), 1000, 1000, 10);
        when(executor.execute(anyList(), eq(source), any()))
                .thenAnswer(invocation -> {
                    List<String> command = invocation.getArgument(0);
                    Files.writeString(Path.of(command.get(5)), "{\"findings\":[]}");
                    return new ScannerProcessExecutor.ProcessResult(true, 0, "done");
                });

        ScanProcessWorker worker = worker(scanService, storage, executor, wrapper);
        worker.execute(5L, source.toString());

        verify(executor).execute(
                eq(List.of("python", wrapper.toAbsolutePath().normalize().toString(),
                        "--source-dir", source.toRealPath().toString(),
                        "--output", uploadRoot.resolve("results").resolve("scan-5").resolve("scored_results.json").toString())),
                eq(source), eq(Duration.ofMinutes(15)));
        verify(scanService).persistScoredResults(eq(5L), any(com.fasterxml.jackson.databind.JsonNode.class));
    }

    @Test
    void recordsNonZeroScannerExitAsFailed() throws Exception {
        Path uploadRoot = Files.createDirectory(tempDirectory.resolve("uploads"));
        Path source = Files.createDirectory(uploadRoot.resolve("source"));
        Path wrapper = Files.writeString(tempDirectory.resolve("scan_wrapper.py"), "print('scanner')");
        ScanService scanService = mock(ScanService.class);
        ScannerProcessExecutor executor = mock(ScannerProcessExecutor.class);
        ScanSourceStorageService storage = new ScanSourceStorageService(uploadRoot.toString(), 1000, 1000, 10);
        when(executor.execute(anyList(), eq(source), any()))
                .thenReturn(new ScannerProcessExecutor.ProcessResult(true, 2, "scanner failed"));

        worker(scanService, storage, executor, wrapper).execute(6L, source.toString());

        verify(scanService).updateScanStatus(6L, "FAILED", "Scanner process exited with code 2: scanner failed");
    }

    @Test
    void clonesGitHubCommitRunsScannerAndCleansRemoteWorkspace() throws Exception {
        Path uploadRoot = Files.createDirectory(tempDirectory.resolve("uploads"));
        Path wrapper = Files.writeString(tempDirectory.resolve("scan_wrapper.py"), "print('scanner')");
        ScanService scanService = mock(ScanService.class);
        ScannerProcessExecutor executor = mock(ScannerProcessExecutor.class);
        ScanSourceStorageService storage = new ScanSourceStorageService(uploadRoot.toString(), 1000, 1000, 10);
        when(executor.execute(anyList(), any(Path.class), any(Duration.class), anyMap()))
                .thenAnswer(invocation -> {
                    List<String> command = invocation.getArgument(0);
                    if (command.contains("clone")) {
                        Files.createDirectories(Path.of(command.get(command.size() - 1)));
                    }
                    return new ScannerProcessExecutor.ProcessResult(true, 0, "git done");
                });
        when(executor.execute(anyList(), any(Path.class), any(Duration.class)))
                .thenAnswer(invocation -> {
                    List<String> command = invocation.getArgument(0);
                    Files.writeString(Path.of(command.get(5)), "{\"findings\":[]}");
                    return new ScannerProcessExecutor.ProcessResult(true, 0, "scanner done");
                });

        worker(scanService, storage, executor, wrapper).executeRemote(
                17L, "https://github.com/acme/demo", "deadbeef1", "main");

        verify(executor, times(3)).execute(anyList(), any(Path.class), any(Duration.class), anyMap());
        verify(scanService).persistScoredResults(eq(17L), any(com.fasterxml.jackson.databind.JsonNode.class));
        verify(scanService, never()).updateScanStatus(eq(17L), eq("FAILED"), anyString());
        assertEquals(0, Files.list(uploadRoot.resolve("remote")).count());
    }

    private ScanProcessWorker worker(
            ScanService scanService,
            ScanSourceStorageService storage,
            ScannerProcessExecutor executor,
            Path wrapper
    ) {
        ScanProcessWorker worker = new ScanProcessWorker(scanService, storage, executor, new ObjectMapper());
        ReflectionTestUtils.setField(worker, "pythonExecutable", "python");
        ReflectionTestUtils.setField(worker, "wrapperPath", wrapper.toString());
        ReflectionTestUtils.setField(worker, "timeout", Duration.ofMinutes(15));
        ReflectionTestUtils.setField(worker, "gitExecutable", "git");
        ReflectionTestUtils.setField(worker, "githubToken", "");
        return worker;
    }
}
