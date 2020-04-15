package com.securityjwt.mysecurityjwt.security.jwt;

import java.util.Date;

import com.securityjwt.mysecurityjwt.security.services.UserDetailsImpl;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtils {

    @Value("${mysecurityjwt.app.jwtSecret}")
    private String jwtSecret;

    @Value("${mysecurityjwt.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().setSubject((userPrincipal.getUsername())).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException se) {
            log.error("Invalid JWT Signature: {}", se.getMessage());
        } catch (MalformedJwtException mje) {
            log.error("Invalid JWT Token: {}", mje.getMessage());
        } catch (ExpiredJwtException eje) {
            log.error("JWT Token was expired: {}", eje.getMessage());
        } catch (UnsupportedJwtException uje) {
            log.error("JWT Token is unsupported: {}", uje.getMessage());
        } catch (IllegalArgumentException iae) {
            log.error("JWT Claims string is empty: {}", iae.getMessage());
        }

        return false;
    }
}