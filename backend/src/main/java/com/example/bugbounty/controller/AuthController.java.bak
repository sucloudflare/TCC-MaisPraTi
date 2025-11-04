package com.example.bugbounty.controller;

import com.example.bugbounty.dto.LoginRequest;
import com.example.bugbounty.entity.User;
import com.example.bugbounty.security.UserPrincipal;
import com.example.bugbounty.service.JwtService;
import com.example.bugbounty.service.MfaService;
import com.example.bugbounty.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final MfaService mfaService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            User saved = userService.registerUser(user);
            return ResponseEntity.ok(Map.of(
                    "message", "Registrado com sucesso!",
                    "username", saved.getUsername(),
                    "email", saved.getEmail()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = userService.findByUsernameOrEmail(request.getUsernameOrEmail());
        if (user == null || !userService.checkPassword(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).body(Map.of("error", "Credenciais inválidas"));
        }

        if (user.isMfaEnabled()) {
            return ResponseEntity.ok(Map.of(
                    "mfaRequired", true,
                    "username", user.getUsername(),
                    "email", user.getEmail()
            ));
        }

        String token = jwtService.generateToken(new UserPrincipal(user));
        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.getUsername(),
                "email", user.getEmail()
        ));
    }

    @PostMapping("/mfa/setup")
    public ResponseEntity<?> setupMfa(@RequestParam String username) throws Exception {
        User user = userService.findByUsername(username);
        if (user == null) return ResponseEntity.badRequest().body(Map.of("error", "Usuário não encontrado"));

        String secret = mfaService.generateSecret();
        userService.updateUserMfaSecret(user.getId(), secret);
        user.setMfaEnabled(true);
        userService.save(user); // AGORA FUNCIONA

        String url = mfaService.getOtpAuthUrl(user.getUsername(), secret);

        return ResponseEntity.ok(Map.of(
                "otpAuthUrl", url,
                "secret", secret
        ));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<?> verifyMfa(@RequestParam String username, @RequestParam String code) throws Exception {
        User user = userService.findByUsername(username);
        if (user == null) return ResponseEntity.badRequest().body(Map.of("error", "Usuário não encontrado"));

        int codeInt = Integer.parseInt(code);
        boolean valid = mfaService.verifyCode(user, codeInt);
        if (!valid) return ResponseEntity.badRequest().body(Map.of("error", "Código MFA inválido"));

        String token = jwtService.generateToken(new UserPrincipal(user));
        return ResponseEntity.ok(Map.of(
                "token", token,
                "username", user.getUsername(),
                "email", user.getEmail()
        ));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        String token = userService.createPasswordResetToken(email);
        if (token == null) return ResponseEntity.badRequest().body(Map.of("error", "Email não encontrado"));
        return ResponseEntity.ok(Map.of("resetToken", token));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        boolean success = userService.resetPassword(token, newPassword);
        if (!success) return ResponseEntity.badRequest().body(Map.of("error", "Token inválido ou expirado"));
        return ResponseEntity.ok(Map.of("message", "Senha redefinida com sucesso"));
    }
}