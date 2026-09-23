package co.kubo.iam.web;

import co.kubo.iam.application.dto.AuthDtos.HealthResponse;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    private final JdbcTemplate jdbcTemplate;

    public HealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/health")
    public HealthResponse health() {
        String db = "UP";
        try {
            jdbcTemplate.queryForObject("select 1", Integer.class);
        } catch (Exception exception) {
            db = "DOWN";
        }
        return new HealthResponse(db.equals("UP") ? "UP" : "DEGRADED", "kubo-iam", db, Instant.now());
    }
}
