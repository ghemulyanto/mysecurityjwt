package com.securityjwt.mysecurityjwt.repository;

import java.util.Optional;

import com.securityjwt.mysecurityjwt.models.ERole;
import com.securityjwt.mysecurityjwt.models.Role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}