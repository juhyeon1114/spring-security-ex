package security.springsecurityex.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.springsecurityex.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
}
