package com.example.ticket.controller;

import com.example.ticket.model.Ticket;
import com.example.ticket.service.TicketService;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.concurrent.Executors;

@Controller
public class TicketController {
    private final TicketService ticketService;

    public TicketController(TicketService ticketService) {
        this.ticketService = ticketService;
    }

    @GetMapping("/ticket")
    public String ticketPage(Model model) {
        model.addAttribute("ticket", ticketService.getTicket());
        return "ticket";
    }

    @GetMapping(value = "/tickets/stream/{id}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamTicket(@PathVariable Long id) {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        Executors.newSingleThreadExecutor().submit(() -> {
            try {
                while (true) {
                    Ticket ticket = ticketService.getTicket();
                    emitter.send(ticket);
                    Thread.sleep(5000);
                }
            } catch (IOException | InterruptedException e) {
                emitter.completeWithError(e);
            }
        });
        return emitter;
    }
}
