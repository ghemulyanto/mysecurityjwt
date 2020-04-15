package com.securityjwt.mysecurityjwt.controller;

import java.util.List;

import com.securityjwt.mysecurityjwt.models.Role;
import com.securityjwt.mysecurityjwt.repository.RoleRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/data")
public class MasterDataController {

    @Autowired
    RoleRepository roleRepository;

    @GetMapping("/roles")
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

}