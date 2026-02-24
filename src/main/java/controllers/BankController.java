package controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import service.BankService;

@Controller
@RequestMapping("/")
public class BankController {

    private final BankService bankService;

    public BankController(BankService bankService) {
        this.bankService = bankService;
    }

    @GetMapping
    public String home() {
        return "redirect:/accounts";
    }

    @GetMapping("/accounts")
    public String viewAccounts(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        if (isAdmin) {
            model.addAttribute("accounts", bankService.getAllAccounts());
            return "admin/view_accounts";
        } else {
            model.addAttribute("accounts", bankService.getAccountsByOwner(email));
            return "client/view_accounts";
        }
    }

    @PostMapping("/accounts/create")
    public String createAccount(@RequestParam String userEmail, RedirectAttributes ra) {
        try {
            bankService.createAccount(userEmail);
            ra.addFlashAttribute("success", "Account created successfully for " + userEmail);
            return "redirect:/accounts?createSuccess=true";
        } catch (Exception e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/accounts";
        }
    }

    @PostMapping("/transaction")
    public String transaction(@RequestParam int accountId,
            @RequestParam String operation,
            @RequestParam double amount,
            @RequestParam(required = false) Integer toAccountId,
            RedirectAttributes ra) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            switch (operation.toUpperCase()) {
                case "DEBIT":
                    bankService.debit(accountId, amount, isAdmin);
                    break;
                case "CREDIT":
                    bankService.credit(accountId, amount, isAdmin);
                    break;
                case "TRANSFER":
                    if (toAccountId == null) {
                        throw new IllegalArgumentException("Destination account ID is required for transfers");
                    }
                    bankService.transfer(accountId, toAccountId, amount, isAdmin);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid operation type: " + operation);
            }
            ra.addFlashAttribute("success", operation + " of " + amount + " € completed successfully");
            return "redirect:/accounts?txSuccess=true";
        } catch (Exception e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/accounts";
        }
    }
}
