package me.uz.app.service;

import lombok.RequiredArgsConstructor;
import me.uz.app.entity.User;
import me.uz.app.repository.UserRepository;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    final UserRepository userRepository;

    @Override
    public Mono<User> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatusCode.valueOf(404), "User not found!")));
    }
}
