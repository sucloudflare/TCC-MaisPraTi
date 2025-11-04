package com.example.bugbounty.service;

import com.example.bugbounty.entity.User;
import com.example.bugbounty.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // ==================== REGISTRO ====================
    public User registerUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new RuntimeException("Username já existe");
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("Email já registrado");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    // ==================== BUSCAS ====================
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User findByUsernameOrEmail(String login) {
        return userRepository.findByUsername(login)
                .orElse(userRepository.findByEmail(login).orElse(null));
    }

    public boolean checkPassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    // ==================== RESET DE SENHA ====================
    public String createPasswordResetToken(String email) {
        User user = findByEmail(email);
        if (user == null) return null;

        String token = UUID.randomUUID().toString();
        user.setResetToken(token);
        user.setResetTokenExpiry(Instant.now().plus(30, ChronoUnit.MINUTES));
        userRepository.save(user);
        return token;
    }

    public boolean resetPassword(String token, String newPassword) {
        Optional<User> optionalUser = userRepository.findByResetToken(token);
        if (optionalUser.isEmpty()) return false;

        User user = optionalUser.get();
        if (user.getResetTokenExpiry() == null || Instant.now().isAfter(user.getResetTokenExpiry())) {
            return false;
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);
        return true;
    }

    // ==================== MFA ====================
    public void updateUserMfaSecret(Long userId, String secret) {
        userRepository.findById(userId).ifPresent(user -> {
            user.setMfaSecret(secret);
            userRepository.save(user);
        });
    }

    // NOVO: save()
    public User save(User user) {
        return userRepository.save(user);
    }
}