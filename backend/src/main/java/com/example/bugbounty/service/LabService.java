package com.example.bugbounty.service;

import com.example.bugbounty.model.Lab;
import com.example.bugbounty.repository.LabRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LabService {

    private final LabRepository repo;

    public LabService(LabRepository repo) {
        this.repo = repo;
    }

    public List<Lab> findAll() {
        return repo.findAll();
    }

    public List<Lab> findCompleted() {
        return repo.findAll().stream()
                .filter(Lab::isCompleted)
                .toList();
    }

    public void markCompleted(String code) {
        repo.findByCode(code).ifPresent(l -> {
            l.setCompleted(true);
            repo.save(l);
        });
    }

    public Lab save(Lab lab) {
        return repo.save(lab);
    }
}
