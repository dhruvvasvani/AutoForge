package com.autoforge;

import com.autoforge.exception.ApiException;
import com.autoforge.service.GitHubPullRequestClient;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GitHubPullRequestClientTest {
    @Test
    void createsRealPullRequestUsingGitHubApiResponse() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://api.example/repos/acme/demo/pulls"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andExpect(jsonPath("$.head").value("security/fix-7"))
                .andExpect(jsonPath("$.base").value("main"))
                .andRespond(withSuccess("""
                        {"number": 123, "html_url": "https://github.com/acme/demo/pull/123", "state": "open"}
                        """, MediaType.APPLICATION_JSON));
        GitHubPullRequestClient client = new GitHubPullRequestClient(builder, "https://api.example", "test-token");

        var result = client.createPullRequest("acme/demo", "main", "security/fix-7", "Security fix", "Review patch");

        assertEquals(123, result.number());
        assertEquals("https://github.com/acme/demo/pull/123", result.url());
        assertEquals("OPEN", result.state());
        server.verify();
    }

    @Test
    void refusesToCreatePullRequestWithoutCredentials() {
        GitHubPullRequestClient client = new GitHubPullRequestClient(
                RestClient.builder(), "https://api.example", "");

        assertThrows(ApiException.class,
                () -> client.createPullRequest("acme/demo", "main", "security/fix-7", "Fix", "Review"));
    }
}
