package co.kubo.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Autenticacion interna de confianza.
 *
 * <p>El API Gateway valida la firma del JWT (RS256 contra el JWKS de este servicio) y propaga la
 * identidad ya verificada en cabeceras. Los servicios de negocio nunca reciben trafico directo:
 * solo son alcanzables dentro de la red privada de contenedores, por lo que confiar en estas
 * cabeceras es seguro en este despliegue. En produccion con cluster se complementa con mTLS.
 */
public class InternalAuthFilter extends OncePerRequestFilter {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_TENANT_ID = "X-Tenant-Id";
    public static final String HEADER_USER_ROLE = "X-User-Role";

    /** Identidad del operador de plataforma (F6.4, ADR-0025): reino propio. */
    public static final String HEADER_PLATFORM_ID = "X-Platform-Admin-Id";
    public static final String HEADER_PLATFORM_EMAIL = "X-Platform-Admin-Email";

    /** Roles validos del negocio: una cabecera forjada no inventa un rol nuevo. */
    private static final Set<String> ROLES =
            Set.of("OWNER", "ADMIN", "SELLER", "ACCOUNTANT", "VIEWER");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // El operador de plataforma no es un usuario de negocio: se autentica con
        // su propia cabecera y su propio rol. El gateway garantiza que un token
        // de negocio no llegue aqui y viceversa.
        String platformId = request.getHeader(HEADER_PLATFORM_ID);
        if (platformId != null
                && !platformId.isBlank()
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            var authentication = new UsernamePasswordAuthenticationToken(
                    platformId, null, List.of(new SimpleGrantedAuthority("ROLE_PLATFORM")));
            authentication.setDetails(request.getHeader(HEADER_PLATFORM_EMAIL));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        String userId = request.getHeader(HEADER_USER_ID);
        if (userId != null && !userId.isBlank() && SecurityContextHolder.getContext().getAuthentication() == null) {
            String role = request.getHeader(HEADER_USER_ROLE);

            // Whitelist: el gateway solo inyecta roles verificados, pero una
            // cabecera forjada no puede inventar un rol nuevo.
            if (role == null || !ROLES.contains(role)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"code\":\"INVALID_ROLE\",\"message\":\"El rol no es valido\"}");
                return;
            }

            List<SimpleGrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_" + role));
            var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
            authentication.setDetails(request.getHeader(HEADER_TENANT_ID));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
