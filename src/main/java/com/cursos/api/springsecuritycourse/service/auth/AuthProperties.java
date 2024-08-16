package com.cursos.api.springsecuritycourse.service.auth;

import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;

public class AuthProperties {
    public final static SecretKey SECRET_KEY_AUTH = Jwts.SIG.HS256.key().build();
}
