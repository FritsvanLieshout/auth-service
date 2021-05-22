package com.kwetter.frits.authservice.repository;

import com.kwetter.frits.authservice.entity.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

@Repository
@Transactional
public interface UserRepository extends CrudRepository<User, Long> {
    User findUserByUsername(String username);
    long deleteByUsername(String username);
}
