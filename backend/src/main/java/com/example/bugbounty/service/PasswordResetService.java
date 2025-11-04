package com.example.bugbounty.service;

import com.example.bugbounty.entity.User;
import com.example.bugbounty.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final SecureRandom random = new SecureRandom();

    public String createResetToken(User user) {
        byte[] tokenBytes = new byte[32];
        random.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        user.setResetToken(token);
        user.setResetTokenExpiry(Instant.now().plusSeconds(3600)); // 1 hora de validade
        userRepository.save(user);

        return token;
    }

    public boolean validateResetToken(User user, String token) {
        return token != null &&
                token.equals(user.getResetToken()) &&
                user.getResetTokenExpiry() != null &&
                Instant.now().isBefore(user.getResetTokenExpiry());
    }

    public void resetPassword(User user, String newPassword, org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder) {
        user.setPassword(encoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);
    }
}
