package com.autoforge;

import com.autoforge.controller.HealthController;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class HealthControllerTest {
    @Test
    void reportsUnavailableWhenDatabaseIsDisconnected() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(2)).thenReturn(false);

        var response = new HealthController(dataSource).healthCheck();

        assertEquals(503, response.getStatusCode().value());
        assertEquals("error", response.getBody().get("status"));
        assertEquals("disconnected", response.getBody().get("database"));
        verify(connection).close();
    }

    @Test
    void reportsHealthyWhenDatabaseIsConnected() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(2)).thenReturn(true);

        var response = new HealthController(dataSource).healthCheck();

        assertEquals(200, response.getStatusCode().value());
        assertEquals("ok", response.getBody().get("status"));
        assertEquals("connected", response.getBody().get("database"));
        verify(connection).close();
    }
}
