package baykov.daniel.cookie_auth.repository;

import baykov.daniel.cookie_auth.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByTokenId(String tokenId);

    @Query(value = "SELECT user_id FROM token WHERE tokenId=?1", nativeQuery = true)
    Long findUserIdByTokenId(String tokenId);

    @Query("SELECT t FROM Token t WHERE t.user.id = :userId AND t.tokenType.id = :tokenTypeId ORDER BY t.createdAt DESC LIMIT 1")
    String findLatestTokenByUserIdAndTokenTypeId(UUID userId, UUID tokenTypeId);
}
