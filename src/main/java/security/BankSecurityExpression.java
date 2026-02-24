package security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import model.Account;
import repository.AccountRepository;

@Component("bankSecurityExpression")
public class BankSecurityExpression {

    private final AccountRepository accountRepository;

    public BankSecurityExpression(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    public boolean isAccountOwner(Authentication authentication, int accountId) {
        String loggedInEmail = authentication.getName();
        Account account = accountRepository.findById(accountId).orElse(null);
        if (account == null) {
            return false;
        }
        return account.getOwner().getEmail().equals(loggedInEmail);
    }
}
