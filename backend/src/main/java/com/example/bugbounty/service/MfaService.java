package com.example.bugbounty.service;

import com.example.bugbounty.entity.User;
import com.example.bugbounty.repository.UserRepository;
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
@RequiredArgsConstructor
public class MfaService {

    private final UserRepository userRepository;
    private final SecureRandom random = new SecureRandom();

    private static final Duration TOTP_PERIOD = Duration.ofSeconds(30);

    // Gera secret base64
    public String generateSecret() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
        keyGenerator.init(160);
        SecretKey key = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // URL para QR code
    public String getOtpAuthUrl(String username, String secret) {
        return "otpauth://totp/BugBounty:" + username + "?secret=" + secret + "&issuer=BugBounty";
    }

    // Verifica código TOTP
    public boolean verifyCode(User user, int code) throws Exception {
        if (user.getMfaSecret() == null) return false;

        byte[] keyBytes = Base64.getDecoder().decode(user.getMfaSecret());
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA1");

        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(TOTP_PERIOD);

        int generated = totp.generateOneTimePassword(key, Instant.now());
        return generated == code;
    }

    // Gera recovery codes (5 códigos de 6 dígitos)
    public List<String> generateRecoveryCodes(User user) {
        List<String> codes = IntStream.range(0, 5)
                .mapToObj(i -> String.format("%06d", random.nextInt(1_000_000)))
                .collect(Collectors.toList());
        user.setRecoveryCodes(String.join(",", codes));
        userRepository.save(user);
        return codes;
    }
}
