package com.autoforge;

import com.autoforge.config.ScanWebSocketHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.Message;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.net.URI;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

class ScanWebSocketHandlerTest {
    @Test
    void redisScanEventsAreForwardedToTheMatchingWebSocketSession() throws Exception {
        ScanWebSocketHandler handler = new ScanWebSocketHandler(new ObjectMapper());
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.getUri()).thenReturn(URI.create("/api/v1/ws/scans/42"));
        when(session.isOpen()).thenReturn(true);
        handler.afterConnectionEstablished(session);

        Message message = mock(Message.class);
        when(message.getBody()).thenReturn(
                "{\"scan_id\":42,\"stage\":\"SCANNING\",\"status\":\"OK\"}".getBytes());
        handler.onMessage(message, null);

        verify(session).sendMessage(argThat(frame ->
                frame instanceof TextMessage && ((TextMessage) frame).getPayload().contains("\"stage\":\"SCANNING\"")));
    }
}
