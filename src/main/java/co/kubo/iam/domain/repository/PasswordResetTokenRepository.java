package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.PasswordResetToken;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /**
     * Descarta los enlaces anteriores sin usar del usuario: pedir uno nuevo invalida el
     * anterior, de modo que solo el ultimo correo recibido sirve.
     */
    @Modifying
    @Query("delete from PasswordResetToken t where t.userId = :userId and t.usedAt is null")
    int deleteUnusedByUserId(@Param("userId") UUID userId);
}
