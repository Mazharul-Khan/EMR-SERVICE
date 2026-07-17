package com.emr.emr_service_ws.repository;

import com.emr.emr_service_ws.entity.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthTokenRepository extends JpaRepository<AuthToken, UUID> {
    
    Optional<AuthToken> findByToken(String token);

    @Modifying
    @Query("UPDATE AuthToken t SET t.isActive = false, t.revokedAt = :now WHERE t.user.userId = :userId AND t.isActive = true")
    void revokeActiveTokens(@Param("userId") UUID userId, @Param("now") LocalDateTime now);
}
