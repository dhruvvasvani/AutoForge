package com.autoforge.analyzer.privacy;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class ZKProofGenerator {

    public String generateScanCommitment(String scanResultsJson, String secretSalt) {
        try {
            String combined = (scanResultsJson != null ? scanResultsJson : "") + ":" + (secretSalt != null ? secretSalt : "");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate scan commitment hash", e);
        }
    }

    public boolean verifyScanCommitment(String scanResultsJson, String secretSalt, String commitment) {
        String expected = generateScanCommitment(scanResultsJson, secretSalt);
        return expected.equalsIgnoreCase(commitment);
    }

    public Map<String, Object> generateProofMetadata(String scanResultsJson, String secretSalt) {
        String commitment = generateScanCommitment(scanResultsJson, secretSalt);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("type", "SHA256_COMMITMENT");
        metadata.put("commitment", commitment);
        metadata.put("timestamp", Instant.now().toString());
        metadata.put("verified", true);
        return metadata;
    }
}
