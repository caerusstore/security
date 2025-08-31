package com.example.ticket;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class TicketMilestoneApplication {
    public static void main(String[] args) {
        SpringApplication.run(TicketMilestoneApplication.class, args);
    }
}
