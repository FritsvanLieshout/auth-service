package com.kwetter.frits.authservice.authentication;

import java.util.Optional;

public interface AuthUserDAO {
    Optional<AuthUser> findAuthUserByUsername(String username);
}
