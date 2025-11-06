package com.example.bugbounty.controller;

import com.example.bugbounty.entity.Job;
import com.example.bugbounty.repository.JobRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/jobs")
@RequiredArgsConstructor
public class JobController {

    private final JobRepository jobRepository;

    @PostMapping
    public ResponseEntity<Job> createJob(@RequestBody Job job) {
        job.setStatus("PENDING");
        Job saved = jobRepository.save(job);
        return ResponseEntity.ok(saved);
    }

    @PostMapping("/test")
    public ResponseEntity<Job> testJob(@RequestBody Map<String, String> payload) {
        String targetUrl = payload.get("targetUrl");
        String vulnerabilityType = payload.get("vulnerabilityType");

        if (targetUrl == null || vulnerabilityType == null) {
            return ResponseEntity.badRequest().build();
        }

        Job job = new Job();
        job.setTargetUrl(targetUrl);
        job.setVulnerabilityType(vulnerabilityType);
        job.setSeverity("Critical");
        job.setStatus("RUNNING");

        Job saved = jobRepository.save(job);
        return ResponseEntity.ok(saved);
    }

    @GetMapping
    public List<Job> getAllJobs() {
        return jobRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Job> getJob(@PathVariable Long id) {
        return jobRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<Job> updateStatus(@PathVariable Long id, @RequestParam String status) {
        Job job = jobRepository.findById(id).orElseThrow();
        job.setStatus(status);
        jobRepository.save(job);
        return ResponseEntity.ok(job);
    }

    @PostMapping("/{id}/result")
    public ResponseEntity<?> receiveResult(@PathVariable Long id, @RequestBody Object report) {
        Job job = jobRepository.findById(id).orElse(null);
        if (job == null) {
            return ResponseEntity.notFound().build();
        }

        job.setStatus("DONE");
        job.setReportPath("/reports/job-" + id + ".txt"); // agora .txt
        jobRepository.save(job);

        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @GetMapping("/{id}/report")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long id) {
        Job job = jobRepository.findById(id).orElse(null);
        if (job == null) {
            return ResponseEntity.notFound().build();
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            StringBuilder txt = new StringBuilder();

            txt.append("=".repeat(50)).append("\n");
            txt.append("        BUG BOUNTY REPORT\n");
            txt.append("=".repeat(50)).append("\n\n");

            txt.append("Generated on: ").append(new Date()).append("\n\n");

            txt.append("Target URL: ").append(job.getTargetUrl()).append("\n");
            txt.append("Vulnerability Type: ").append(job.getVulnerabilityType()).append("\n");
            txt.append("Severity: ").append(job.getSeverity()).append("\n");
            txt.append("Status: ").append(job.getStatus()).append("\n");
            txt.append("Report Path: ").append(job.getReportPath()).append("\n\n");

            txt.append("-".repeat(50)).append("\n");
            txt.append("Generated automatically by BugBounty API.\n");
            txt.append("-".repeat(50)).append("\n");

            byte[] txtBytes = txt.toString().getBytes(StandardCharsets.UTF_8);
            baos.write(txtBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            headers.setContentDispositionFormData("attachment", "job-report-" + id + ".txt");

            return new ResponseEntity<>(baos.toByteArray(), headers, HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}