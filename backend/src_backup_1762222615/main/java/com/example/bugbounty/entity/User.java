package com.example.bugbounty.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(nullable = false)
    private String password;

    // ====================== MFA ======================
    @Column(nullable = false)
    private boolean mfaEnabled = false;

    @Column(length = 255)
    private String mfaSecret;

    @Column(columnDefinition = "TEXT")
    private String recoveryCodes;

    // =================== RECUPERAÇÃO DE SENHA ===================
    @Column(length = 255)
    private String resetToken;

    @Column
    private java.time.Instant resetTokenExpiry;
}
