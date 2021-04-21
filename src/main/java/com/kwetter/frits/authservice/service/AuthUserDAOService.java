package com.kwetter.frits.authservice.service;

import com.google.common.collect.Lists;
import com.kwetter.frits.authservice.authentication.AuthUser;
import com.kwetter.frits.authservice.authentication.AuthUserDAO;
import com.kwetter.frits.authservice.entity.User;
import com.kwetter.frits.authservice.entity.UserRole;
import com.kwetter.frits.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("auth")
public class AuthUserDAOService implements AuthUserDAO {

    private UserRepository userRepository;

    @Autowired
    public AuthUserDAOService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public Optional<AuthUser> findAuthUserByUsername(String username) {
        return getAuthUsers().stream().filter(authUser -> username.equals(authUser.getUsername())).findFirst();
    }

    private List<AuthUser> getAuthUsers() {
        List<AuthUser> applicationUsers = Lists.newArrayList();
        for (User user : userRepository.findAll()) {
            applicationUsers.add(new AuthUser(user.getUsername(), user.getPassword(), getRole(user.getRole()).getGrantedAuthorities(), true, true, true, true ));
        }

        return applicationUsers;
    }

    private UserRole getRole(String role) {
        switch (role) {
            case "KWETTER_ADMIN":
                return UserRole.KWETTER_ADMIN;
            case "KWETTER_MODERATOR":
                return UserRole.KWETTER_MODERATOR;
            default:
                return UserRole.KWETTER_USER;
        }
    }
}
