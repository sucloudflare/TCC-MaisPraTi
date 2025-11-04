package com.example.bugbounty.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.List;

/**
 * Entidade User com:
 * - MFA (TOTP + Recovery Codes)
 * - Reset de senha
 * - Segurança Spring Security (enabled)
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true) // Permite .toBuilder()
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(nullable = false, length = 255)
    private String password;

    // =================== SEGURANÇA SPRING ===================
    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private boolean enabled = true;

    // ====================== MFA (TOTP) ======================
    @Column(name = "mfa_enabled", nullable = false)
    @Builder.Default
    private boolean mfaEnabled = false;

    @Column(name = "mfa_secret", length = 255)
    private String mfaSecret;

    // Recovery Codes: CSV (ex: "123456,789012")
    @Column(name = "recovery_codes", columnDefinition = "TEXT")
    private String recoveryCodes;

    // =================== RECUPERAÇÃO DE SENHA ===================
    @Column(name = "reset_token", length = 255)
    private String resetToken;

    @Column(name = "reset_token_expiry")
    private Instant resetTokenExpiry;

    // ========= MÉTODOS AUXILIARES =========

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public List<String> getRecoveryCodesList() {
        if (recoveryCodes == null || recoveryCodes.isBlank()) {
            return List.of();
        }
        return List.of(recoveryCodes.split(","));
    }

    public void setRecoveryCodesList(List<String> codes) {
        this.recoveryCodes = codes != null && !codes.isEmpty() ? String.join(",", codes) : null;
    }

    public void clearResetToken() {
        this.resetToken = null;
        this.resetTokenExpiry = null;
    }
}