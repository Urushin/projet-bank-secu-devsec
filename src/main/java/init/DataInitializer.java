package init;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import model.Account;
import model.User;
import repository.AccountRepository;
import repository.UserRepository;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, AccountRepository accountRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            // ADMIN
            User admin = new User("admin@bank.com", "Admin Bank", passwordEncoder.encode("admin123"), "ADMIN");
            userRepository.save(admin);

            // CLIENT 1
            User client1 = new User("client1@bank.com", "Client One", passwordEncoder.encode("client123"), "CLIENT");
            userRepository.save(client1);

            // CLIENT 2
            User client2 = new User("client2@bank.com", "Client Two", passwordEncoder.encode("client123"), "CLIENT");
            userRepository.save(client2);

            // Accounts mapping
            Account adminAcc = new Account(admin);
            adminAcc.credit(50000.0);
            accountRepository.save(adminAcc);

            Account c1Acc1 = new Account(client1);
            c1Acc1.credit(1500.0);
            accountRepository.save(c1Acc1);

            Account c1Acc2 = new Account(client1);
            c1Acc2.credit(200.0);
            accountRepository.save(c1Acc2);

            Account c2Acc1 = new Account(client2);
            c2Acc1.credit(3500.0);
            accountRepository.save(c2Acc1);

            System.out.println("Base users and accounts initialized.");
        }
    }
}
