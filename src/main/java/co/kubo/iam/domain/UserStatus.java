package co.kubo.iam.domain;

/** Estado del usuario. {@code DISABLED} bloquea el inicio de sesion sin borrar la historia. */
public enum UserStatus {
    ACTIVE,
    DISABLED
}
