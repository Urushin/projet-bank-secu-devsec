package model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "users")
public class User {

	@Id
	@Email(message = "Email format is invalid")
	@NotBlank(message = "Email is required")
	@Column(nullable = false, unique = true, length = 255)
	private String email;

	@NotBlank(message = "Name is required")
	@Size(max = 100, message = "Name must not exceed 100 characters")
	@Column(nullable = false, length = 100)
	private String name;

	@NotBlank(message = "Password is required")
	@Column(nullable = false)
	private String password;

	@NotBlank(message = "Role is required")
	@Column(nullable = false, length = 50)
	private String roles;

	public User() {
	}

	public User(String email, String name, String password, String roles) {
		this.email = email;
		this.name = name;
		this.password = password;
		this.roles = roles;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}

	public boolean isAdmin() {
		return this.roles != null && this.roles.toUpperCase().contains("ADMIN");
	}
}
