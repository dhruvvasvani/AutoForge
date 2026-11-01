package com.autoforge.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
@Slf4j
public class ScanWebSocketHandler extends TextWebSocketHandler implements MessageListener {
    private final Map<Long, List<WebSocketSession>> sessionsByJobId = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    public ScanWebSocketHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onMessage(Message message, byte[] pattern) {
        try {
            var event = objectMapper.readTree(message.getBody());
            var scanIdNode = event.path("scan_id");
            if (!scanIdNode.canConvertToLong()) {
                log.warn("Ignoring Redis scan event without scan_id.");
                return;
            }
            broadcast(scanIdNode.asLong(), event);
        } catch (Exception ex) {
            log.error("Unable to process Redis scan event: {}", ex.getMessage(), ex);
        }
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        Long jobId = extractJobId(session.getUri());
        if (jobId != null) {
            sessionsByJobId.computeIfAbsent(jobId, k -> new CopyOnWriteArrayList<>()).add(session);
            log.info("WebSocket connected for scan job {}: session {}", jobId, session.getId());
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        Long jobId = extractJobId(session.getUri());
        if (jobId != null) {
            List<WebSocketSession> sessions = sessionsByJobId.get(jobId);
            if (sessions != null) {
                sessions.remove(session);
                if (sessions.isEmpty()) {
                    sessionsByJobId.remove(jobId);
                }
            }
            log.info("WebSocket disconnected for scan job {}: session {}", jobId, session.getId());
        }
    }

    public void broadcast(Long jobId, Object message) {
        List<WebSocketSession> sessions = sessionsByJobId.get(jobId);
        if (sessions == null || sessions.isEmpty()) {
            return;
        }

        try {
            String json = objectMapper.writeValueAsString(message);
            TextMessage textMessage = new TextMessage(json);
            for (WebSocketSession session : sessions) {
                if (session.isOpen()) {
                    try {
                        session.sendMessage(textMessage);
                    } catch (Exception e) {
                        log.warn("Failed to send WebSocket message to session {}: {}", session.getId(), e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to serialize WebSocket message for job {}: {}", jobId, e.getMessage());
        }
    }

    private Long extractJobId(URI uri) {
        if (uri == null) return null;
        String path = uri.getPath();
        try {
            String[] segments = path.split("/");
            for (int i = 0; i < segments.length - 1; i++) {
                if ("scans".equalsIgnoreCase(segments[i])) {
                    return Long.parseLong(segments[i + 1]);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
}
