package com.standard.base.repository;

import java.util.Optional;

import com.standard.base.models.ERole;
import com.standard.base.models.Role;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String> {
  Optional<Role> findByName(ERole roleUser);
}
