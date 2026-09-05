package com.autoforge.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Slf4j
@Service
public class ASTAnalyzerService {

    @Value("${ast.analyzer.python.path:3_ast_analyzer}")
    private String astAnalyzerPath;

    @Value("${ast.analyzer.python.script:week4_pipeline/pipeline_cli.py}")
    private String astAnalyzerScript;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> analyzeCode(String sourceFile, String scanResultsJson) {
        try {
            log.info("Starting AST analysis for: {}", sourceFile);

            File tempScanFile = createTempFile("scan_input_", ".json", scanResultsJson);
            File tempOutputFile = File.createTempFile("ast_output_", ".json");

            try {
                String pythonCommand = buildPythonCommand(sourceFile, tempScanFile.getAbsolutePath(), tempOutputFile.getAbsolutePath());

                log.debug("Executing: {}", pythonCommand);

                ProcessBuilder processBuilder = new ProcessBuilder("python", "-c", pythonCommand);
                processBuilder.redirectErrorStream(true);

                Process process = processBuilder.start();
                int exitCode = process.waitFor();

                if (exitCode != 0) {
                    String error = readProcessError(process);
                    log.error("AST analyzer failed with exit code {}: {}", exitCode, error);
                    throw new RuntimeException("AST analyzer failed: " + error);
                }

                String output = new String(Files.readAllBytes(tempOutputFile.toPath()));
                log.debug("AST analyzer output: {}", output);

                Map<String, Object> result = objectMapper.readValue(output, Map.class);

                log.info("AST analysis completed. Actionable findings: {}", 
                         result.getOrDefault("actionable_findings", List.of()).toString().length());

                return result;

            } finally {
                tempScanFile.delete();
                tempOutputFile.delete();
            }

        } catch (Exception e) {
            log.error("Error in AST analysis", e);
            throw new RuntimeException("AST analysis failed: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> analyzeFunction(String sourceFile, String functionName) {
        try {
            log.info("Analyzing function reachability: {} in {}", functionName, sourceFile);

            String pythonCode = String.format(
                "import sys\n" +
                "sys.path.insert(0, '%s')\n" +
                "from week1_foundations.parser_setup import TreeSitterParser\n" +
                "from week2_prototype.noise_filter import CallGraphExtractor\n" +
                "from week3_reachability.ast_engine import ReachabilityAnalyzer\n" +
                "with open('%s', 'r') as f:\n" +
                "    source = f.read()\n" +
                "analyzer = ReachabilityAnalyzer(source)\n" +
                "reachable = analyzer.analyze_reachability({})\n" +
                "result = {'function': '%s', 'is_reachable': '%s' in reachable}\n" +
                "import json\n" +
                "print(json.dumps(result))",
                astAnalyzerPath, sourceFile, "{}", functionName
            );

            Process process = Runtime.getRuntime().exec(new String[]{"python", "-c", pythonCode});
            String output = readProcessOutput(process);

            return objectMapper.readValue(output, Map.class);

        } catch (Exception e) {
            log.error("Error analyzing function reachability", e);
            return Map.of("error", e.getMessage());
        }
    }

    private String buildPythonCommand(String sourceFile, String scanResultsFile, String outputFile) {
        return String.format(
            "import sys\n" +
            "import json\n" +
            "sys.path.insert(0, '%s')\n" +
            "from week1_foundations.parser_setup import TreeSitterParser\n" +
            "from week2_prototype.noise_filter import CallGraphExtractor\n" +
            "from week3_reachability.ast_engine import ReachabilityAnalyzer\n" +
            "from week5_scoring.risk_scorer import RiskScorer\n" +
            "\n" +
            "with open('%s', 'r') as f:\n" +
            "    source_code = f.read()\n" +
            "with open('%s', 'r') as f:\n" +
            "    scan_results = json.load(f)\n" +
            "\n" +
            "parser = TreeSitterParser()\n" +
            "extractor = CallGraphExtractor()\n" +
            "analyzer = ReachabilityAnalyzer(source_code)\n" +
            "scorer = RiskScorer()\n" +
            "\n" +
            "root = parser.parse(source_code)\n" +
            "functions_info, call_graph, _ = extractor.extract(source_code)\n" +
            "reachable = analyzer.analyze_reachability(call_graph)\n" +
            "\n" +
            "findings = scan_results.get('findings', scan_results.get('results', []))\n" +
            "filtered = []\n" +
            "for f in findings:\n" +
            "    func = f.get('function', 'unknown')\n" +
            "    if func in reachable:\n" +
            "        f['reachability'] = 'REACHABLE_CODE'\n" +
            "        priority = scorer.score(f.get('severity', 'INFO'), 'REACHABLE_CODE')\n" +
            "        f['priority'] = priority\n" +
            "        filtered.append(f)\n" +
            "    else:\n" +
            "        f['reachability'] = 'UNREACHABLE_NOISE'\n" +
            "\n" +
            "result = {\n" +
            "    'total_findings': len(findings),\n" +
            "    'actionable_findings': filtered,\n" +
            "    'reachable_count': len(reachable),\n" +
            "    'unreachable_count': len(set(functions_info.keys()) - reachable),\n" +
            "    'noise_reduction_percent': f\"{(len(findings) - len(filtered)) / max(len(findings), 1) * 100:.1f}%%\"\n" +
            "}\n" +
            "with open('%s', 'w') as f:\n" +
            "    json.dump(result, f, indent=2)",
            astAnalyzerPath, sourceFile, scanResultsFile, outputFile
        );
    }

    private File createTempFile(String prefix, String suffix, String content) throws IOException {
        File file = File.createTempFile(prefix, suffix);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
        return file;
    }

    private String readProcessOutput(Process process) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }

    private String readProcessError(Process process) throws IOException {
        StringBuilder error = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                error.append(line).append("\n");
            }
        }
        return error.toString();
    }

    public boolean validateEnvironment() {
        try {
            String checkCommand = String.format(
                "import sys; sys.path.insert(0, '%s'); " +
                "from week1_foundations.parser_setup import TreeSitterParser; " +
                "from week5_scoring.risk_scorer import RiskScorer; " +
                "print('OK')",
                astAnalyzerPath
            );

            Process process = Runtime.getRuntime().exec(new String[]{"python", "-c", checkCommand});
            int exitCode = process.waitFor();

            return exitCode == 0;

        } catch (Exception e) {
            log.error("AST environment validation failed", e);
            return false;
        }
    }
}

