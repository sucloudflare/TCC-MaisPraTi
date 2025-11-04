package com.example.bugbounty.service;

import com.example.bugbounty.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretBase64;

    @Value("${jwt.expiration:86400000}")
    private long expiration;

    @Value("${jwt.issuer:bugbounty-tcc}")
    private String issuer;

    // Cache da chave para performance
    private SecretKey signingKey;

    private SecretKey getSigningKey() {
        if (signingKey == null) {
            byte[] keyBytes = Base64.getDecoder().decode(secretBase64);
            signingKey = Keys.hmacShaKeyFor(keyBytes);
        }
        return signingKey;
    }

    /**
     * Gera token JWT com claims extras do UserPrincipal
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        if (userDetails instanceof UserPrincipal userPrincipal) {
            if (userPrincipal.getId() != null) {
                claims.put("userId", userPrincipal.getId());
            }
            if (userPrincipal.getEmail() != null) {
                claims.put("email", userPrincipal.getEmail());
            }
        }

        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .setIssuer(issuer)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Valida token contra UserDetails (padrão Spring Security)
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extrai username (subject)
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrai claim genérico
     */
    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrai todas as claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Verifica se o token expirou
     */
    private boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    // MÉTODOS AUXILIARES (USADOS NO CONTROLLER)

    /**
     * Extrai UserPrincipal completo do token (sem validação de expiração)
     */
    public UserPrincipal extractUserPrincipal(String token) {
        Claims claims = extractAllClaims(token);
        String username = claims.getSubject();
        Long userId = claims.get("userId", Long.class);
        String email = claims.get("email", String.class);

        UserPrincipal principal = new UserPrincipal();
        principal.setUsername(username);
        principal.setId(userId);
        principal.setEmail(email);
        // authorities não são armazenadas no token (opcional)
        return principal;
    }

    /**
     * Valida token e retorna UserPrincipal (se válido)
     */
    public UserPrincipal validateAndGetPrincipal(String token, UserDetails userDetails) {
        if (validateToken(token, userDetails)) {
            return extractUserPrincipal(token);
        }
        return null;
    }
}