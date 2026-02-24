package controllers;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Global exception handler — eliminates all 500 Internal Server Errors
 * by catching unhandled exceptions and converting them to user-friendly
 * redirects.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public String handleBadRequest(IllegalArgumentException ex, RedirectAttributes ra) {
        ra.addFlashAttribute("error", ex.getMessage());
        return "redirect:/accounts";
    }

    @ExceptionHandler(AccessDeniedException.class)
    public String handleAccessDenied(AccessDeniedException ex, RedirectAttributes ra) {
        ra.addFlashAttribute("error", "Access Denied: You are not authorized to perform this action.");
        return "redirect:/accounts";
    }

    @ExceptionHandler(Exception.class)
    public String handleGeneral(Exception ex, RedirectAttributes ra) {
        ra.addFlashAttribute("error", "An unexpected error occurred. Please try again.");
        return "redirect:/accounts";
    }
}
