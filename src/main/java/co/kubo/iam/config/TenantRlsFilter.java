package co.kubo.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Interceptor de tenant: fija el contexto de Row Level Security por peticion (P-02).
 *
 * <p>Cada peticion corre dentro de una transaccion y publica una de dos marcas:
 *
 * <ul>
 *   <li>{@code app.tenant_id}: la cabecera {@code X-Tenant-Id} que el gateway propaga del JWT.
 *       Con ella, las politicas de RLS solo dejan ver las filas de ese negocio.
 *   <li>{@code app.system}: operaciones que por diseno cruzan negocios (autenticacion por
 *       correo, rotacion de tokens, cadena de auditoria global, semilla).
 * </ul>
 *
 * <p>La marca es local a la transaccion ({@code set_config(..., true)}): al terminar la
 * peticion desaparece y no puede filtrarse a otra que reutilice la conexion. Una cabecera de
 * tenant que no sea un UUID valido se rechaza con 400 en vez de degradar a modo sistema.
 */
@Component
public class TenantRlsFilter extends OncePerRequestFilter {

    public static final String HEADER_TENANT_ID = "X-Tenant-Id";

    private static final Logger log = LoggerFactory.getLogger(TenantRlsFilter.class);

    private final TransactionTemplate transactionTemplate;
    private final JdbcTemplate jdbcTemplate;

    public TenantRlsFilter(PlatformTransactionManager transactionManager, JdbcTemplate jdbcTemplate) {
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String rawTenant = request.getHeader(HEADER_TENANT_ID);
        String tenantId = normalize(rawTenant);

        if (rawTenant != null && !rawTenant.isBlank() && tenantId == null) {
            log.warn("Cabecera {} invalida; se rechaza la peticion", HEADER_TENANT_ID);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write(
                    "{\"code\":\"INVALID_TENANT\",\"message\":\"El negocio indicado no es valido\"}");
            return;
        }

        try {
            transactionTemplate.executeWithoutResult(status -> {
                applyContext(tenantId);
                try {
                    chain.doFilter(request, response);
                } catch (IOException | ServletException exception) {
                    throw new FilterChainFailure(exception);
                }
            });
        } catch (FilterChainFailure failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            if (cause instanceof ServletException servletException) {
                throw servletException;
            }
            throw failure;
        } catch (UnexpectedRollbackException rollback) {
            // Un error de negocio (por ejemplo, credenciales invalidas) marca la
            // transaccion como rollback-only mientras el manejador de errores ya
            // escribio la respuesta 401. La reversion es correcta y el cliente ya
            // fue informado: solo se ignora si la respuesta salio. Si no salio,
            // es un fallo real y debe propagarse.
            if (response.isCommitted()) {
                log.debug("Transaccion revertida despues de responder al cliente: {}", rollback.getMessage());
            } else {
                throw rollback;
            }
        }
    }

    private void applyContext(String tenantId) {
        if (tenantId != null) {
            jdbcTemplate.queryForObject(
                    "select set_config('app.tenant_id', ?, true)", String.class, tenantId);
        } else {
            jdbcTemplate.queryForObject(
                    "select set_config('app.system', 'on', true)", String.class);
        }
    }

    private String normalize(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(header.trim()).toString();
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    /** Envuelve las excepciones verificadas para poder atravesar el lambda de la transaccion. */
    private static final class FilterChainFailure extends RuntimeException {

        FilterChainFailure(Throwable cause) {
            super(cause);
        }
    }
}
