package com.autoforge;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("demo")
class ScanMetricsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void storesMetricsForAuthenticatedUserAndKeepsHistoryPrivate() throws Exception {
        String firstToken = registerAndGetToken("metrics-first");
        String secondToken = registerAndGetToken("metrics-second");
        Map<String, Object> metrics = Map.of(
                "scan_timestamp", "2026-01-02T03:04:05Z",
                "files_received", 3,
                "files_analyzed", 2,
                "total_findings", 4,
                "reachable_findings", 1,
                "unreachable_findings", 2,
                "unverified_findings", 1,
                "noise_reduction_pct", 75.0
        );

        mockMvc.perform(post("/api/scan-metrics")
                        .header("Authorization", "Bearer " + firstToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("metrics", metrics))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.metrics.total_findings").value(4));

        mockMvc.perform(get("/api/scan-metrics")
                        .header("Authorization", "Bearer " + firstToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.scans[0].metrics.noise_reduction_pct").value(75.0));

        mockMvc.perform(get("/api/scan-metrics")
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(0));
    }

    @Test
    void rejectsInvalidMetricCountsAndUnauthenticatedRequests() throws Exception {
        Map<String, Object> invalidMetrics = Map.of(
                "scan_timestamp", "2026-01-02T03:04:05Z",
                "files_received", 1,
                "files_analyzed", 2,
                "total_findings", 0,
                "reachable_findings", 0,
                "unreachable_findings", 0,
                "unverified_findings", 0
        );

        mockMvc.perform(post("/api/scan-metrics")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("metrics", invalidMetrics))))
                .andExpect(status().isForbidden());

        String token = registerAndGetToken("metrics-invalid");
        mockMvc.perform(post("/api/scan-metrics")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("metrics", invalidMetrics))))
                .andExpect(status().isBadRequest());
    }

    private String registerAndGetToken(String label) throws Exception {
        String email = label + "-" + UUID.randomUUID() + "@example.com";
        String request = objectMapper.writeValueAsString(Map.of(
                "fullName", "Metrics Test",
                "email", email,
                "password", "password123"
        ));
        String response = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode body = objectMapper.readTree(response);
        return body.get("token").asText();
    }
}
