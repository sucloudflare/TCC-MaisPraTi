package com.example.bugbounty.model;

public class TestRequest {
    private String targetUrl;
    private String vulnerabilityType;
    private String payload;

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }
    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }
}