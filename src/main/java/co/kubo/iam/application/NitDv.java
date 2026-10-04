package co.kubo.iam.application;

/**
 * Digito de verificacion del NIT colombiano (algoritmo oficial de la DIAN).
 *
 * <p>Se calcula con los pesos 3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67 y 71
 * aplicados de derecha a izquierda; el resto de la division por 11 es el digito, salvo que sea
 * 10 u 11, casos en que es 0 o 1 respectivamente (aqui: {@code resto < 2 -> resto}).
 *
 * <p>Se calcula en el servidor para que el negocio no tenga que conocerlo: al registrar el NIT,
 * el DV queda consistente y el XML de la factura sale correcto.
 */
public final class NitDv {

    private static final int[] PESOS = {3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71};

    private NitDv() {
    }

    /** DV (un digito) del NIT, o {@code null} si el NIT no es numerico. */
    public static String calcular(String nit) {
        if (nit == null || nit.isBlank()) {
            return null;
        }

        String limpio = nit.trim();
        if (!limpio.chars().allMatch(Character::isDigit)) {
            return null;
        }

        int suma = 0;
        int posicion = 0;
        for (int i = limpio.length() - 1; i >= 0; i--) {
            suma += (limpio.charAt(i) - '0') * PESOS[posicion % PESOS.length];
            posicion++;
        }

        int resto = suma % 11;
        return String.valueOf(resto < 2 ? resto : 11 - resto);
    }
}
