package com.example.bugbounty.service;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;

@Service
public class TxtReportService {

    public String generateReport(String targetUrl, String status, String reportPath) {
        try {
            File file = new File(reportPath);
            file.getParentFile().mkdirs();

            StringBuilder txt = new StringBuilder();

            txt.append("=".repeat(50)).append("\n");
            txt.append("        BUG BOUNTY REPORT\n");
            txt.append("=".repeat(50)).append("\n\n");

            txt.append("Target URL: ").append(targetUrl).append("\n");
            txt.append("Generated At: ").append(LocalDateTime.now()).append("\n");
            txt.append("Status: ").append(status).append("\n\n");

            txt.append("-".repeat(50)).append("\n");
            txt.append("This report contains vulnerability analysis results.\n");
            txt.append("-".repeat(50)).append("\n\n");

            txt.append("Generated automatically by BugBounty API.\n");

            Files.writeString(Paths.get(reportPath), txt.toString());

            return "TXT generated successfully: " + reportPath;

        } catch (IOException e) {
            e.printStackTrace();
            return "Error generating TXT: " + e.getMessage();
        }
    }
}