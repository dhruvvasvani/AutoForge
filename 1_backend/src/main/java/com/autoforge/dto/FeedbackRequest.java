package com.autoforge.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FeedbackRequest {
    @NotNull
    @JsonProperty("finding_id")
    private Long findingId;

    @NotNull
    @Pattern(regexp = "DISMISS|FALSE_POSITIVE|ACCEPT_PATCH")
    @JsonProperty("action")
    private String action;

    @JsonProperty("fix_id")
    private Long fixId;

    @Size(max = 2000)
    private String comment;
}
