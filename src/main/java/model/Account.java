package model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "accounts")
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int accountId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "owner_email", nullable = false)
    private User owner;

    @Column(nullable = false)
    private double balance;

    public Account() {
    }

    public Account(User owner) {
        this.owner = owner;
        this.balance = 0.0;
    }

    public int getAccountId() {
        return accountId;
    }

    public void setAccountId(int accountId) {
        this.accountId = accountId;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public double getBalance() {
        return balance;
    }

    public void setBalance(double balance) {
        this.balance = balance;
    }

    public void credit(double amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Credit amount must be positive");
        }
        this.balance += amount;
    }

    public void debit(double amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Debit amount must be positive");
        }
        if (amount > this.balance) {
            throw new IllegalArgumentException("Insufficient funds: balance is " + this.balance + " €");
        }
        this.balance -= amount;
    }
}
