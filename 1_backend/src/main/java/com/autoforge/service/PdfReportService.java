package com.autoforge.service;

import com.autoforge.entity.Finding;
import com.autoforge.entity.Scan;
import com.autoforge.exception.ApiException;
import com.autoforge.dto.PolicyEvaluationRequest;
import com.autoforge.repository.FindingRepository;
import com.autoforge.repository.ScanRepository;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class PdfReportService {
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final PolicyEngine policyEngine;

    public PdfReportService(ScanRepository scanRepository, FindingRepository findingRepository, PolicyEngine policyEngine) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.policyEngine = policyEngine;
    }

    @Transactional(readOnly = true)
    public byte[] generate(Long scanId, String userEmail) {
        Scan scan = scanRepository.findVisibleScanById(scanId, userEmail)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));
        List<Finding> findings = findingRepository.findByScanId(scanId);
        PolicyEvaluationRequest policyRequest = new PolicyEvaluationRequest();
        policyRequest.setScanId(scanId);
        var policyResult = policyEngine.evaluate(policyRequest);

        List<String> lines = new ArrayList<>();
        lines.add("AutoForge Security Audit Report");
        lines.add("Scan ID: " + scan.getId());
        lines.add("Status: " + scan.getStatus());
        lines.add("Commit: " + (scan.getCommitSha() == null ? "N/A" : scan.getCommitSha()));
        lines.add("Branch: " + (scan.getBranch() == null ? "N/A" : scan.getBranch()));
        lines.add("Total findings: " + findings.size());
        lines.add("Quality gate: " + policyResult.getStatus());
        lines.add("Quality gate details: " + policyResult.getReason());
        lines.add("");
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            lines.add((i + 1) + ". [" + finding.getSeverity() + "] " + finding.getTitle());
            lines.add("Rule: " + finding.getRuleId());
            lines.add("Location: " + finding.getFilePath() + ":" + finding.getLineNumber());
            lines.add("Reachability: " + (finding.getReachabilityStatus() == null
                    ? finding.getIsReachable() == null ? "UNKNOWN" : finding.getIsReachable() ? "REACHABLE" : "UNREACHABLE"
                    : finding.getReachabilityStatus()));
            if (finding.getCodeSnippet() != null && !finding.getCodeSnippet().isBlank()) {
                lines.add("Code: " + finding.getCodeSnippet());
            }
            lines.add("");
        }

        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            PDType1Font font = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            PDPage page = new PDPage();
            document.addPage(page);
            PDPageContentStream content = new PDPageContentStream(document, page);
            float y = page.getMediaBox().getHeight() - 50;
            content.beginText();
            content.setFont(font, 10);
            content.newLineAtOffset(45, y);
            for (String line : lines) {
                for (String wrapped : wrap(line, 100)) {
                    if (y < 45) {
                        content.endText();
                        content.close();
                        page = new PDPage();
                        document.addPage(page);
                        content = new PDPageContentStream(document, page);
                        y = page.getMediaBox().getHeight() - 50;
                        content.beginText();
                        content.setFont(font, 10);
                        content.newLineAtOffset(45, y);
                    }
                    content.showText(toWinAnsi(wrapped));
                    content.newLineAtOffset(0, -14);
                    y -= 14;
                }
            }
            content.endText();
            content.close();
            document.save(output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to generate the PDF security report.", ex);
        }
    }

    private List<String> wrap(String value, int width) {
        List<String> wrapped = new ArrayList<>();
        String text = value == null ? "" : value.replaceAll("[\\r\\n\\t]+", " ");
        while (text.length() > width) {
            int breakAt = text.lastIndexOf(' ', width);
            if (breakAt <= 0) breakAt = width;
            wrapped.add(text.substring(0, breakAt));
            text = text.substring(breakAt).stripLeading();
        }
        wrapped.add(text);
        return wrapped;
    }

    private String toWinAnsi(String value) {
        StringBuilder text = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> text.appendCodePoint(
                (codePoint >= 32 && codePoint <= 126) || (codePoint >= 160 && codePoint <= 255) ? codePoint : '?'));
        return text.toString();
    }
}
