package com.autoforge.pipeline.webhook;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

@RestController
@RequestMapping("/api/webhooks")
public class GithubWebhookController {

    // Webhook secret set karega GitHub repo settings > Webhooks me
    // Yahi secret application.properties me bhi rakhna: github.webhook.secret=your_secret_here
    @Value("${github.webhook.secret}")
    private String webhookSecret;

    @PostMapping("/github")
    public ResponseEntity<String> handleGithubWebhook(
            @RequestBody String payload,
            @RequestHeader("X-Hub-Signature-256") String signatureHeader
    ) {
        // Step 1: Signature verify karo
        boolean isValid = verifySignature(payload, signatureHeader, webhookSecret);

        if (!isValid) {
            return ResponseEntity.status(401).body("Invalid signature");
        }

        // Step 2: TODO - payload parse karo (repo name, commit SHA, branch nikaalo)
        // Step 3: TODO - Scan entity create karo DB me (status=PENDING)
        // Step 4: TODO - Redis queue me scan job push karo

        System.out.println("Webhook received and verified: " + payload);

        return ResponseEntity.ok("Webhook received");
    }

    private boolean verifySignature(String payload, String signatureHeader, String secret) {
        try {
            if (signatureHeader == null || !signatureHeader.startsWith("sha256=")) {
                return false;
            }

            String receivedHash = signatureHeader.substring("sha256=".length());

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);

            byte[] hashBytes = mac.doFinal(payload.getBytes());
            String computedHash = HexFormat.of().formatHex(hashBytes);

            return computedHash.equals(receivedHash);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}