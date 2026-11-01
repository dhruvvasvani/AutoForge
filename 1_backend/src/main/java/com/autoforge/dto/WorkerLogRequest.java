package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class WorkerLogRequest {
    @JsonProperty("job_id")
    private Long jobId;

    @JsonProperty("level")
    private String level = "INFO";

    @JsonProperty("message")
    private String message;

    @JsonProperty("progress")
    private Integer progress;

    @JsonProperty("timestamp")
    private Instant timestamp = Instant.now();
}
