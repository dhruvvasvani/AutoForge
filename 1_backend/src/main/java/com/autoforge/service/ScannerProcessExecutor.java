package com.autoforge.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;

@org.springframework.stereotype.Component
public class ScannerProcessExecutor {
    private static final int MAX_CAPTURED_OUTPUT_BYTES = 65536;

    public ProcessResult execute(List<String> command, Path workingDirectory, Duration timeout)
            throws IOException, InterruptedException {
        return execute(command, workingDirectory, timeout, Map.of());
    }

    public ProcessResult execute(List<String> command, Path workingDirectory, Duration timeout, Map<String, String> environment)
            throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command)
                .directory(workingDirectory.toFile())
                .redirectErrorStream(true);
        processBuilder.environment().putAll(environment);
        Process process = processBuilder.start();

        ByteArrayOutputStream capturedOutput = new ByteArrayOutputStream();
        AtomicReference<IOException> outputError = new AtomicReference<>();
        Thread outputReader = new Thread(() -> drainOutput(process, capturedOutput, outputError), "scanner-output-reader");
        outputReader.setDaemon(true);
        outputReader.start();

        boolean finished;
        try {
            finished = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                destroyProcessTree(process);
                process.waitFor();
            }
            outputReader.join();
        } catch (InterruptedException ex) {
            destroyProcessTree(process);
            throw ex;
        }
        if (outputError.get() != null) {
            throw outputError.get();
        }

        return new ProcessResult(finished, finished ? process.exitValue() : -1,
                capturedOutput.toString(StandardCharsets.UTF_8));
    }

    private void drainOutput(Process process, ByteArrayOutputStream capturedOutput, AtomicReference<IOException> outputError) {
        byte[] buffer = new byte[4096];
        int captured = 0;
        try (var output = process.getInputStream()) {
            int read;
            while ((read = output.read(buffer)) != -1) {
                int remaining = MAX_CAPTURED_OUTPUT_BYTES - captured;
                if (remaining > 0) {
                    int toCapture = Math.min(read, remaining);
                    capturedOutput.write(buffer, 0, toCapture);
                    captured += toCapture;
                }
            }
        } catch (IOException ex) {
            outputError.set(ex);
        }
    }

    private void destroyProcessTree(Process process) {
        process.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
    }

    public record ProcessResult(boolean finished, int exitCode, String output) {
    }
}
