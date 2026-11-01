package com.autoforge.service;

import com.autoforge.exception.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.InvalidPathException;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

@Service
public class ScanSourceStorageService {
    private final Path uploadRoot;
    private final long maxUploadBytes;
    private final long maxExtractedBytes;
    private final int maxArchiveEntries;

    public ScanSourceStorageService(
            @Value("${autoforge.scanner.upload-directory:uploads}") String uploadDirectory,
            @Value("${autoforge.scanner.max-upload-bytes:20971520}") long maxUploadBytes,
            @Value("${autoforge.scanner.max-extracted-bytes:536870912}") long maxExtractedBytes,
            @Value("${autoforge.scanner.max-archive-entries:10000}") int maxArchiveEntries
    ) {
        this.uploadRoot = Path.of(uploadDirectory).toAbsolutePath().normalize();
        this.maxUploadBytes = maxUploadBytes;
        this.maxExtractedBytes = maxExtractedBytes;
        this.maxArchiveEntries = maxArchiveEntries;
    }

    public Path storeZip(MultipartFile archive) throws IOException {
        if (archive == null || archive.isEmpty()) {
            throw badRequest("A non-empty ZIP archive is required.");
        }
        if (archive.getSize() > maxUploadBytes) {
            throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE, "ZIP archive exceeds the configured upload limit.");
        }
        String originalName = archive.getOriginalFilename();
        if (originalName == null || !originalName.toLowerCase().endsWith(".zip")) {
            throw badRequest("The uploaded source archive must have a .zip filename.");
        }

        Files.createDirectories(uploadRoot);
        Path workspace = uploadRoot.resolve(UUID.randomUUID().toString()).normalize();
        Path sourceDirectory = workspace.resolve("source");
        Files.createDirectories(sourceDirectory);
        try (InputStream input = archive.getInputStream()) {
            extractZip(input, sourceDirectory);
            return sourceDirectory.toRealPath();
        } catch (IOException | RuntimeException ex) {
            try {
                deleteTree(workspace);
            } catch (IOException cleanupFailure) {
                ex.addSuppressed(cleanupFailure);
            }
            if (ex instanceof ZipException) {
                throw badRequest("The uploaded file is not a valid ZIP archive.");
            }
            throw ex;
        }
    }

    public Path validateSourceDirectory(String sourcePath) throws IOException {
        if (sourcePath == null || sourcePath.isBlank()) {
            throw badRequest("A source directory is required.");
        }
        Files.createDirectories(uploadRoot);
        Path allowedRoot = uploadRoot.toRealPath();
        Path candidate;
        try {
            candidate = Path.of(sourcePath).toRealPath();
        } catch (IOException | InvalidPathException ex) {
            throw badRequest("Source directory does not exist or is invalid.");
        }
        if (candidate.equals(allowedRoot) || !candidate.startsWith(allowedRoot) || !Files.isDirectory(candidate)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Source directory must be inside the configured upload directory.");
        }
        return candidate;
    }

    public Path resultFileFor(Long scanId) throws IOException {
        Path resultsDirectory = uploadRoot.resolve("results").resolve("scan-" + scanId).normalize();
        if (!resultsDirectory.startsWith(uploadRoot)) {
            throw new IOException("Invalid scan result path.");
        }
        Files.createDirectories(resultsDirectory);
        return resultsDirectory.resolve("scored_results.json");
    }

    public Path createRemoteWorkspace() throws IOException {
        Path remoteRoot = uploadRoot.resolve("remote").normalize();
        if (!remoteRoot.startsWith(uploadRoot)) {
            throw new IOException("Invalid remote workspace path.");
        }
        Files.createDirectories(remoteRoot);
        return Files.createTempDirectory(remoteRoot, "scan-");
    }

    public void deleteRemoteWorkspace(Path workspace) throws IOException {
        Path remoteRoot = uploadRoot.resolve("remote").toAbsolutePath().normalize();
        Path candidate = workspace.toAbsolutePath().normalize();
        if (!candidate.getParent().equals(remoteRoot) || !candidate.startsWith(remoteRoot)) {
            throw new IOException("Refusing to delete a workspace outside the remote scan directory.");
        }
        deleteTree(candidate);
    }

    public String displayPath(Path sourceDirectory) {
        Path relative = uploadRoot.relativize(sourceDirectory.toAbsolutePath().normalize());
        return relative.toString().replace('\\', '/');
    }

    private void extractZip(InputStream archive, Path destination) throws IOException {
        int entryCount = 0;
        long extractedBytes = 0;
        int filesExtracted = 0;
        byte[] buffer = new byte[8192];
        try (ZipInputStream zip = new ZipInputStream(archive)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entryCount > maxArchiveEntries) {
                    throw badRequest("ZIP archive contains too many entries.");
                }

                String entryName = entry.getName().replace('\\', '/');
                if (entryName.startsWith("/") || entryName.matches("^[A-Za-z]:.*")) {
                    throw badRequest("ZIP archive contains an absolute path.");
                }
                Path relative = Path.of(entryName).normalize();
                if (relative.toString().isBlank() && entry.isDirectory()) {
                    zip.closeEntry();
                    continue;
                }
                if (relative.isAbsolute() || relative.startsWith("..") || relative.toString().isBlank()) {
                    throw badRequest("ZIP archive contains an unsafe path.");
                }

                Path target = destination.resolve(relative).normalize();
                if (!target.startsWith(destination)) {
                    throw badRequest("ZIP archive contains an unsafe path.");
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    try (OutputStream output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
                        int read;
                        while ((read = zip.read(buffer)) != -1) {
                            extractedBytes += read;
                            if (extractedBytes > maxExtractedBytes) {
                                throw new ApiException(HttpStatus.PAYLOAD_TOO_LARGE, "Extracted ZIP content exceeds the configured limit.");
                            }
                            output.write(buffer, 0, read);
                        }
                    }
                    filesExtracted++;
                }
                zip.closeEntry();
            }
        }
        if (filesExtracted == 0) {
            throw badRequest("ZIP archive does not contain any files.");
        }
    }

    private void deleteTree(Path directory) throws IOException {
        if (!Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private ApiException badRequest(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, message);
    }
}
