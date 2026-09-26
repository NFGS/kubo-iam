package co.kubo.iam.domain;

import java.util.Arrays;
import java.util.Optional;

/**
 * Planes comerciales (P-27, ADR-0021).
 *
 * Los limites viven donde vive el recurso: IAM es dueno de los usuarios, asi
 * que aqui esta su cupo; el ERP aplica los suyos (bodegas) con el mismo nombre
 * de plan, que viaja en el token. Duplicar una tabla de tres numeros es mas
 * barato —y mas honesto— que un servicio de cuotas en el camino de cada
 * peticion.
 */
public enum Plan {
    COMMUNITY("community", 5, 2),
    PRO("pro", 25, 10);

    private final String code;
    private final int maxUsers;
    private final int maxWarehouses;

    Plan(String code, int maxUsers, int maxWarehouses) {
        this.code = code;
        this.maxUsers = maxUsers;
        this.maxWarehouses = maxWarehouses;
    }

    public String code() {
        return code;
    }

    public int maxUsers() {
        return maxUsers;
    }

    public int maxWarehouses() {
        return maxWarehouses;
    }

    public static Optional<Plan> byCode(String code) {
        return Arrays.stream(values()).filter(plan -> plan.code.equals(code)).findFirst();
    }

    /** Un plan desconocido (dato migrado) se trata como el mas restrictivo. */
    public static Plan byCodeOrDefault(String code) {
        return byCode(code).orElse(COMMUNITY);
    }
}
