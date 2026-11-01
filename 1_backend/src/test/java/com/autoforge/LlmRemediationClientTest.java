package com.autoforge;

import com.autoforge.entity.Finding;
import com.autoforge.exception.ApiException;
import com.autoforge.service.LlmRemediationClient;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class LlmRemediationClientTest {
    private static final String PATCH = "--- a/src/Dao.java\n+++ b/src/Dao.java\n@@ -1 +1 @@\n-old\n+new";

    @Test
    void sendsReachableFindingToConfiguredProviderAndReturnsUnifiedDiff() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://llm.example/v1/chat/completions"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer test-key"))
                .andRespond(withSuccess("{\"choices\":[{\"message\":{\"content\":\"" + PATCH.replace("\n", "\\n") + "\"}}]}",
                        org.springframework.http.MediaType.APPLICATION_JSON));
        LlmRemediationClient client = new LlmRemediationClient(
                builder, "https://llm.example/v1/chat/completions", "test-key", "test-model");
        Finding finding = reachableFinding();

        assertEquals(PATCH, client.generatePatch(finding));
        server.verify();
    }

    @Test
    void doesNotCallProviderForUnknownReachabilityOrMissingConfiguration() {
        LlmRemediationClient unconfigured = new LlmRemediationClient(
                RestClient.builder(), "https://llm.example/v1/chat/completions", "", "");
        ApiException noConfig = assertThrows(ApiException.class, () -> unconfigured.generatePatch(reachableFinding()));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, noConfig.getStatus());

        Finding unknown = reachableFinding();
        unknown.setIsReachable(null);
        LlmRemediationClient configured = new LlmRemediationClient(
                RestClient.builder(), "https://llm.example/v1/chat/completions", "key", "model");
        ApiException notReachable = assertThrows(ApiException.class, () -> configured.generatePatch(unknown));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, notReachable.getStatus());
    }

    private Finding reachableFinding() {
        Finding finding = new Finding();
        finding.setId(5L);
        finding.setRuleId("SEC-1");
        finding.setTitle("Unsafe query");
        finding.setFilePath("src/Dao.java");
        finding.setLineNumber(3);
        finding.setSeverity("HIGH");
        finding.setCodeSnippet("query(input)");
        finding.setIsReachable(true);
        return finding;
    }
}
