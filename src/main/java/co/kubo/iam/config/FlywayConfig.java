package co.kubo.iam.config;

import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Ejecucion explicita de las migraciones de esquema.
 *
 * <p>En Spring Boot 4 la autoconfiguracion de Flyway vive en un modulo aparte
 * que no llega con el arranque de datos; en lugar de depender de esa pieza, el
 * servicio invoca Flyway directamente. La ventaja adicional es que la migracion
 * deja de ser magia: es una linea visible del arranque y falla ruidosamente si
 * el esquema no se puede aplicar.
 */
@Configuration
public class FlywayConfig {

    private static final Logger log = LoggerFactory.getLogger(FlywayConfig.class);

    @Bean
    public Flyway flyway(DataSource dataSource) {
        Flyway flyway = Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .baselineOnMigrate(true)
                .validateOnMigrate(true)
                .load();

        flyway.migrate();
        log.info("Migraciones de esquema verificadas y aplicadas");
        return flyway;
    }
}
