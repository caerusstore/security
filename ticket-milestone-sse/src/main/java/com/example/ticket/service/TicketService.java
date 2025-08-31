package com.example.ticket.service;

import com.example.ticket.model.Ticket;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@Service
public class TicketService {
    private Ticket ticket;

    public TicketService() {
        List<String> milestones = Arrays.asList("Created", "In Progress", "QA", "Done");
        ticket = new Ticket(1L, "Sample Ticket", milestones, 0, LocalDateTime.now().plusSeconds(30));
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void moveToNext() {
        if (ticket.getCurrentIndex() < ticket.getMilestones().size() - 1) {
            ticket.setCurrentIndex(ticket.getCurrentIndex() + 1);
            ticket.setCurrentDeadline(LocalDateTime.now().plusSeconds(30));
        }
    }
}
