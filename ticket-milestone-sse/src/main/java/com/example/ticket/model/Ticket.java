package com.example.ticket.model;

import java.time.LocalDateTime;
import java.util.List;

public class Ticket {
    private Long id;
    private String title;
    private List<String> milestones;
    private int currentIndex;
    private LocalDateTime currentDeadline;

    public Ticket(Long id, String title, List<String> milestones, int currentIndex, LocalDateTime currentDeadline) {
        this.id = id;
        this.title = title;
        this.milestones = milestones;
        this.currentIndex = currentIndex;
        this.currentDeadline = currentDeadline;
    }

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public List<String> getMilestones() { return milestones; }
    public int getCurrentIndex() { return currentIndex; }
    public void setCurrentIndex(int currentIndex) { this.currentIndex = currentIndex; }
    public LocalDateTime getCurrentDeadline() { return currentDeadline; }
    public void setCurrentDeadline(LocalDateTime currentDeadline) { this.currentDeadline = currentDeadline; }
}
