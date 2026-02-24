package repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

import model.Account;
import model.User;

@Repository
public interface AccountRepository extends JpaRepository<Account, Integer> {
    List<Account> findByOwner(User owner);
}
