package com.kwetter.frits.authservice.entity;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.kwetter.frits.authservice.entity.UserPermissions.*;

public enum UserRole {
    KWETTER_ADMIN(Sets.newHashSet(TIMELINE_READ, TWEET_READ, TWEET_WRITE, TWEET_DELETE, USER_DELETE, USER_LOGOUT)),
    KWETTER_MODERATOR(Sets.newHashSet(TIMELINE_READ, TWEET_READ, TWEET_DELETE, USER_DELETE, USER_LOGOUT)),
    KWETTER_USER(Sets.newHashSet(TIMELINE_READ, TWEET_READ, TWEET_WRITE, TWEET_UPDATE, TWEET_DELETE, USER_READ, USER_UPDATE, USER_DELETE, USER_LOGOUT, SEARCH_WRITE));

    private final Set<UserPermissions> permissions;

    UserRole(Set<UserPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<UserPermissions> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }

}