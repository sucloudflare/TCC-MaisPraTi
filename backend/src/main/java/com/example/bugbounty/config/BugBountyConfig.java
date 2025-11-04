// src/main/java/com/example/bugbounty/config/BugBountyConfig.java
package com.example.bugbounty.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "bugbounty")
public class BugBountyConfig {
    private String userAgent;
    private int requestDelayMs;
    private int connectTimeoutMs;
    private int readTimeoutMs;
    private List<String> allowedDomains;

    // getters e setters
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public int getRequestDelayMs() { return requestDelayMs; }
    public void setRequestDelayMs(int requestDelayMs) { this.requestDelayMs = requestDelayMs; }

    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public void setConnectTimeoutMs(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs; }

    public int getReadTimeoutMs() { return readTimeoutMs; }
    public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }

    public List<String> getAllowedDomains() { return allowedDomains; }
    public void setAllowedDomains(List<String> allowedDomains) { this.allowedDomains = allowedDomains; }
}
