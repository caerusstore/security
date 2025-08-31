package com.example.ticket.scheduler;

import com.example.ticket.service.TicketService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class TicketScheduler {
    private final TicketService ticketService;

    public TicketScheduler(TicketService ticketService) {
        this.ticketService = ticketService;
    }

    @Scheduled(fixedRate = 5000)
    public void autoMove() {
        if (LocalDateTime.now().isAfter(ticketService.getTicket().getCurrentDeadline())) {
            ticketService.moveToNext();
        }
    }
}
