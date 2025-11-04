package com.example.bugbounty.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.lang.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSocket
public class AppConfig implements WebSocketConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(AppConfig.class);

    @Override
    public void registerWebSocketHandlers(@NonNull WebSocketHandlerRegistry registry) {
        logger.info("✅ Registrando WebSocket no endpoint /ws");
        registry.addHandler(new MyWebSocketHandler(), "/ws")
                .setAllowedOrigins("*"); // permitir frontend de qualquer origem
    }

    private static class MyWebSocketHandler extends TextWebSocketHandler {
        private static final Logger logger = LoggerFactory.getLogger(MyWebSocketHandler.class);

        @Override
        public void handleTextMessage(@NonNull WebSocketSession session, @NonNull TextMessage message) throws Exception {
            logger.info("Mensagem WebSocket recebida: {}", message.getPayload());
            session.sendMessage(new TextMessage("Echo: " + message.getPayload()));
        }
    }
}
