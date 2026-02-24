package com.auditbank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@ComponentScan(basePackages = { "controllers", "init", "model", "repository", "security", "service", "com.auditbank" })
@EnableJpaRepositories(basePackages = "repository")
@EntityScan(basePackages = "model")
public class AuditBankApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditBankApplication.class, args);
    }

}
