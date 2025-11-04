// src/main/java/com/example/bugbounty/controller/JobController.java
package com.example.bugbounty.controller;

import com.example.bugbounty.entity.Job;
import com.example.bugbounty.repository.JobRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

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

    @GetMapping
    public List<Job> getAllJobs() {
        return jobRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Job> getJob(@PathVariable Long id) {
        Optional<Job> job = jobRepository.findById(id);
        return job.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
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
        job.setReportPath("/reports/job-" + id + ".json");
        jobRepository.save(job);

        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}