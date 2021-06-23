package com.kamronbek.jwt.service;

import com.kamronbek.jwt.dto.AuthenticationResponse;
import com.kamronbek.jwt.dto.RegistrationRequest;
import com.kamronbek.jwt.dto.RegistrationResponse;
import com.kamronbek.jwt.model.User;
import com.kamronbek.jwt.model.UserRole;
import com.kamronbek.jwt.repository.UserRepository;
import com.kamronbek.jwt.util.JwtUtils;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(
                        () -> new UsernameNotFoundException("User with email " + email + " not found"));
    }

    public AuthenticationResponse authenticate() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return new AuthenticationResponse(
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getRole().name()
        );
    }

    public ResponseEntity<?> register(RegistrationRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());
        if (optionalUser.isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(null);
        }

        User user = new User(
                null,
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                passwordEncoder.encode(request.getPassword()),
                UserRole.ROLE_USER,
                LocalDateTime.now()
        );

        userRepository.save(user);
        String token = JwtUtils.generateToken(user);

        return ResponseEntity.ok().body(
                new RegistrationResponse(
                        token,
                        user.getFirstName(),
                        user.getLastName(),
                        user.getEmail(),
                        user.getRole().name()
                )
        );
    }
}
