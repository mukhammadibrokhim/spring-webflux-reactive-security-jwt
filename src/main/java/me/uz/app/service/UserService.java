package me.uz.app.service;

import me.uz.app.entity.User;
import reactor.core.publisher.Mono;

public interface UserService {
    Mono<User> findByUsername(String username);
}
