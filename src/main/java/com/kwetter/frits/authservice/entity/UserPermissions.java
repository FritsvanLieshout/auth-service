package com.kwetter.frits.authservice.entity;

public enum UserPermissions {
    TIMELINE_READ("timeline:read"),
    TWEET_READ("tweet:read"),
    TWEET_WRITE("tweet:write"),
    TWEET_UPDATE("tweet:update"),
    TWEET_DELETE("tweet:delete"),
    TWEET_LIKE("tweet:like"),
    USER_READ("user:read"),
    USER_UPDATE("user:update"),
    USER_DELETE("user:delete"),
    USER_LOGOUT("user:logout"),
    SEARCH_WRITE("search:write");

    private final String permission;

    UserPermissions(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
