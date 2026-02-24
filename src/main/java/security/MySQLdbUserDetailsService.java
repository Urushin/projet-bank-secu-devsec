package security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import model.User;
import repository.UserRepository;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class MySQLdbUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public MySQLdbUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findById(username)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));

        List<SimpleGrantedAuthority> authorities = Arrays.stream(user.getRoles().split(","))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.trim().toUpperCase()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                authorities);
    }
}
