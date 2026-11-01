package com.autoforge.analyzer.remediation;

import org.springframework.stereotype.Component;

@Component
public class RemediationEngine {

    public String generateSqlFix(String fileContent, int lineNumber, String unsafeVar) {
        String oldPattern1 = "executeQuery(\"SELECT * FROM users WHERE id = \" + " + unsafeVar + ")";
        String newPattern1 = "prepareStatement(\"SELECT * FROM users WHERE id = ?\").setString(1, " + unsafeVar + ")";

        if (fileContent.contains(oldPattern1)) {
            return fileContent.replace(oldPattern1, newPattern1);
        }

        String oldPattern2 = "\"SELECT * FROM users WHERE id = \" + " + unsafeVar;
        String newPattern2 = "\"SELECT * FROM users WHERE id = ?\" /* parameterized with " + unsafeVar + " */";
        return fileContent.replace(oldPattern2, newPattern2);
    }

    public String generateUnifiedDiff(String originalContent, String patchedContent, String filePath) {
        StringBuilder diff = new StringBuilder();
        diff.append("--- a/").append(filePath).append("\n");
        diff.append("+++ b/").append(filePath).append("\n");
        diff.append("@@ -1,1 +1,1 @@\n");

        String[] origLines = originalContent.split("\r?\n");
        String[] patchLines = patchedContent.split("\r?\n");

        int max = Math.max(origLines.length, patchLines.length);
        for (int i = 0; i < max; i++) {
            String orig = i < origLines.length ? origLines[i] : null;
            String patch = i < patchLines.length ? patchLines[i] : null;

            if (orig != null && !orig.equals(patch)) {
                diff.append("-").append(orig).append("\n");
            }
            if (patch != null && !patch.equals(orig)) {
                diff.append("+").append(patch).append("\n");
            }
        }
        return diff.toString();
    }
}
