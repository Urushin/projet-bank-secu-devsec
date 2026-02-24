package service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import model.Account;
import model.User;
import repository.AccountRepository;
import repository.UserRepository;

import java.util.List;

@Service
@Transactional
public class BankService {

    private final AccountRepository accountRepository;
    private final UserRepository userRepository;

    public BankService(AccountRepository accountRepository, UserRepository userRepository) {
        this.accountRepository = accountRepository;
        this.userRepository = userRepository;
    }

    // ---- Read Operations ----

    public List<Account> getAllAccounts() {
        return accountRepository.findAll();
    }

    public List<Account> getAccountsByOwner(String email) {
        User owner = userRepository.findById(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
        return accountRepository.findByOwner(owner);
    }

    public Account getAccountById(int accountId) {
        return accountRepository.findById(accountId)
                .orElseThrow(() -> new IllegalArgumentException("Account #" + accountId + " does not exist"));
    }

    // ---- Write Operations ----

    @PreAuthorize("hasRole('ADMIN')")
    public void createAccount(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        String sanitized = email.trim().toLowerCase();
        User user = userRepository.findById(sanitized)
                .orElseThrow(() -> new IllegalArgumentException("No registered user with email: " + sanitized));
        Account account = new Account(user);
        accountRepository.save(account);
    }

    // ---- Transaction Logic ----

    /**
     * Business rule enforcement:
     * - ADMIN: operations must exceed 1000 €
     * - CLIENT: operations are capped at 1000 €
     * - All amounts must be strictly positive
     */
    private void validateAmount(double amount, boolean isAdmin) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Amount must be a positive number");
        }
        if (isAdmin && amount <= 1000) {
            throw new IllegalArgumentException("Administrator operations must exceed 1 000 €");
        }
        if (!isAdmin && amount > 1000) {
            throw new IllegalArgumentException("Client operations are limited to 1 000 € maximum");
        }
    }

    @PreAuthorize("hasRole('ADMIN') or (hasRole('CLIENT') and @bankSecurityExpression.isAccountOwner(authentication, #accountId))")
    public void credit(int accountId, double amount, boolean isAdmin) {
        validateAmount(amount, isAdmin);
        Account account = getAccountById(accountId);
        account.credit(amount);
        accountRepository.save(account);
    }

    @PreAuthorize("hasRole('ADMIN') or (hasRole('CLIENT') and @bankSecurityExpression.isAccountOwner(authentication, #accountId))")
    public void debit(int accountId, double amount, boolean isAdmin) {
        validateAmount(amount, isAdmin);
        Account account = getAccountById(accountId);
        account.debit(amount); // debit() already checks for insufficient funds
        accountRepository.save(account);
    }

    @PreAuthorize("hasRole('ADMIN') or (hasRole('CLIENT') and @bankSecurityExpression.isAccountOwner(authentication, #fromAccountId))")
    public void transfer(int fromAccountId, int toAccountId, double amount, boolean isAdmin) {
        if (fromAccountId == toAccountId) {
            throw new IllegalArgumentException("Cannot transfer to the same account");
        }
        validateAmount(amount, isAdmin);
        Account fromAccount = getAccountById(fromAccountId);
        Account toAccount = getAccountById(toAccountId);

        fromAccount.debit(amount); // checks for insufficient funds
        toAccount.credit(amount);

        accountRepository.save(fromAccount);
        accountRepository.save(toAccount);
    }
}
