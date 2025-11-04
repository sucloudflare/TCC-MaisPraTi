package com.example.bugbounty.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

public class TotpUtil {

    private static final String ISSUER = "BugBountyApp";

    public static String generateSecret() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
        keyGenerator.init(160);
        SecretKey key = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static boolean verifyCode(String base32Secret, int code) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base32Secret);
        SecretKey key = new javax.crypto.spec.SecretKeySpec(decodedKey, "HmacSHA1");

        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();
        int generatedCode = totp.generateOneTimePassword(key, Instant.now());
        return generatedCode == code;
    }

    public static String getOtpAuthUrl(String username, String secret) {
        String encoded = URLEncoder.encode(username, StandardCharsets.UTF_8);
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", ISSUER, encoded, secret, ISSUER);
    }
}
