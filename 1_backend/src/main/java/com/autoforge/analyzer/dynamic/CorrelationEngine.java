package com.autoforge.analyzer.dynamic;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class CorrelationEngine {

    public boolean verifyVulnerability(int staticSinkLine, List<Map<String, Object>> runtimeEvents) {
        if (runtimeEvents == null || runtimeEvents.isEmpty()) {
            return false;
        }

        for (Map<String, Object> event : runtimeEvents) {
            Object lineObj = event.get("line");
            Object execObj = event.get("executed");

            int eventLine = -1;
            if (lineObj instanceof Number) {
                eventLine = ((Number) lineObj).intValue();
            } else if (lineObj instanceof String) {
                try {
                    eventLine = Integer.parseInt((String) lineObj);
                } catch (NumberFormatException ignored) {}
            }

            boolean isExecuted = Boolean.TRUE.equals(execObj) || "true".equalsIgnoreCase(String.valueOf(execObj));

            if (eventLine == staticSinkLine && isExecuted) {
                return true;
            }
        }
        return false;
    }
}
