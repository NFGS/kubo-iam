package co.kubo.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
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

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String userId = request.getHeader(HEADER_USER_ID);
        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            String role = request.getHeader(HEADER_USER_ROLE);
            List<SimpleGrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_" + (role == null ? "USER" : role)));
            var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
            authentication.setDetails(request.getHeader(HEADER_TENANT_ID));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
