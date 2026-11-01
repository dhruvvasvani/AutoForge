package com.autoforge;

import com.autoforge.exception.ApiException;
import com.autoforge.service.ScanSourceStorageService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ScanSourceStorageServiceTest {
    @TempDir
    Path tempDirectory;

    @Test
    void extractsZipUnderConfiguredRoot() throws Exception {
        ScanSourceStorageService storage = storage();
        MockMultipartFile archive = zip("source.zip", "src/Main.java", "class Main {}");

        Path source = storage.storeZip(archive);

        assertTrue(source.startsWith(tempDirectory.toAbsolutePath().normalize()));
        assertEquals("class Main {}", Files.readString(source.resolve("src/Main.java")));
        assertTrue(storage.displayPath(source).replace('\\', '/').endsWith("/source"));
    }

    @Test
    void rejectsZipSlipEntriesAndCleansPartialExtraction() throws Exception {
        ScanSourceStorageService storage = storage();
        MockMultipartFile archive = zip("source.zip", "../escape.txt", "not allowed");

        assertThrows(ApiException.class, () -> storage.storeZip(archive));
        assertFalse(Files.exists(tempDirectory.resolve("escape.txt")));
        try (var children = Files.list(tempDirectory)) {
            assertEquals(0, children.count());
        }
    }

    @Test
    void rejectsLocalSourceOutsideConfiguredRoot() throws Exception {
        ScanSourceStorageService storage = storage();
        Path outside = Files.createDirectory(tempDirectory.resolveSibling("outside-source"));

        try {
            assertThrows(ApiException.class, () -> storage.validateSourceDirectory(outside.toString()));
        } finally {
            Files.deleteIfExists(outside);
        }
    }

    private ScanSourceStorageService storage() {
        return new ScanSourceStorageService(tempDirectory.toString(), 1024 * 1024, 1024 * 1024, 100);
    }

    private MockMultipartFile zip(String filename, String entryName, String contents) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry(entryName));
            zip.write(contents.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return new MockMultipartFile("file", filename, "application/zip", bytes.toByteArray());
    }
}
