package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Revoca todos los tokens vigentes de un usuario. Se usa cuando se detecta la reutilizacion de
     * un token ya rotado: la familia completa se invalida por precaucion.
     */
    @Modifying
    @Query(
            "update RefreshToken r set r.revokedAt = :now "
                    + "where r.userId = :userId and r.revokedAt is null")
    int revokeAllByUserId(@Param("userId") UUID userId, @Param("now") Instant now);
}
