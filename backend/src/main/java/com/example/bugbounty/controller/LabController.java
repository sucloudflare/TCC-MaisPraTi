package com.example.bugbounty.controller;

import com.example.bugbounty.model.Lab;
import com.example.bugbounty.service.LabService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/labs")
@CrossOrigin(origins = "*")
public class LabController {

    private final LabService service;

    public LabController(LabService service) {
        this.service = service;
    }

    @GetMapping
    public List<Lab> getAllLabs() {
        return service.findAll();
    }

    @GetMapping("/completed")
    public List<Lab> getCompletedLabs() {
        return service.findCompleted();
    }

    @PostMapping
    public Lab createLab(@RequestBody Lab lab) {
        return service.save(lab);
    }

    @PostMapping("/{code}/complete")
    public void markLabAsCompleted(@PathVariable String code) {
        service.markCompleted(code);
    }
}
