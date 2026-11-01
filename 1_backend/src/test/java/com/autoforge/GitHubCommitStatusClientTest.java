package com.autoforge;

import com.autoforge.exception.ApiException;
import com.autoforge.service.GitHubCommitStatusClient;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GitHubCommitStatusClientTest {
    @Test
    void postsSuccessfulCommitStatusWhenGatePasses() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://api.example/repos/acme/demo/statuses/0123456789abcdef0123456789abcdef01234567"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andExpect(jsonPath("$.state").value("success"))
                .andExpect(jsonPath("$.context").value("AutoForge/quality-gate"))
                .andRespond(withSuccess("""
                        {"id": 501, "state": "success"}
                        """, MediaType.APPLICATION_JSON));
        GitHubCommitStatusClient client = new GitHubCommitStatusClient(
                builder, "https://api.example", "test-token");

        client.publish("acme/demo", "0123456789abcdef0123456789abcdef01234567", true, "Quality gate passed.");

        server.verify();
    }

    @Test
    void requiresCredentialsAndValidRepositoryAndCommit() {
        GitHubCommitStatusClient withoutToken = new GitHubCommitStatusClient(
                RestClient.builder(), "https://api.example", "");
        assertThrows(ApiException.class,
                () -> withoutToken.publish("acme/demo", "0123456789abcdef0123456789abcdef01234567", true, "Passed"));

        GitHubCommitStatusClient configured = new GitHubCommitStatusClient(
                RestClient.builder(), "https://api.example", "test-token");
        assertThrows(ApiException.class, () -> configured.publish("not-a-slug", "bad-sha", false, "Failed"));
    }
}
