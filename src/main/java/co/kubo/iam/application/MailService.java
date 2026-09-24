package co.kubo.iam.application;

/**
 * Puerto de salida de correo.
 *
 * <p>El transporte se elige con {@code KUBO_MAIL_TRANSPORT}: {@code log} (por defecto) guarda
 * el mensaje en el buzon de demostracion de la base de datos, sin salir del servidor;
 * {@code smtp} lo entrega a un servidor de correo real.
 */
public interface MailService {

    void send(String recipient, String subject, String body);
}
