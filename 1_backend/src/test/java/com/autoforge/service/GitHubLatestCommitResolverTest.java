package com.autoforge.service;

import com.autoforge.exception.ApiException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GitHubLatestCommitResolverTest {

    @Test
    void resolvesCommitFromPublicRepositoryDefaultBranch() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        GitHubLatestCommitResolver resolver = new GitHubLatestCommitResolver(builder);

        server.expect(requestTo("https://api.github.com/repos/octo/demo"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"default_branch\":\"main\"}", org.springframework.http.MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.github.com/repos/octo/demo/commits?sha=main&per_page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "[{\"sha\":\"0123456789abcdef0123456789abcdef01234567\"}]",
                        org.springframework.http.MediaType.APPLICATION_JSON
                ));

        assertEquals(
                "0123456789abcdef0123456789abcdef01234567",
                resolver.resolve("octo/demo")
        );
        server.verify();
    }

    @Test
    void rejectsMalformedRepositoryNameBeforeRequestingGitHub() {
        GitHubLatestCommitResolver resolver = new GitHubLatestCommitResolver(RestClient.builder());

        ApiException error = assertThrows(ApiException.class, () -> resolver.resolve("https://example.com/repo"));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatus());
    }

    @Test
    void explainsThatPrivateRepositoriesNeedServerSideCredentials() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        GitHubLatestCommitResolver resolver = new GitHubLatestCommitResolver(builder);
        server.expect(requestTo("https://api.github.com/repos/octo/private"))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators.withStatus(HttpStatus.NOT_FOUND));

        ApiException error = assertThrows(ApiException.class, () -> resolver.resolve("octo/private"));

        assertEquals(HttpStatus.NOT_FOUND, error.getStatus());
        org.junit.jupiter.api.Assertions.assertTrue(error.getMessage().contains("server-side GitHub credentials"));
        server.verify();
    }
}
