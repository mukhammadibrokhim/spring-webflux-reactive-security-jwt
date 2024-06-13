package me.uz.app.contorller;

import lombok.RequiredArgsConstructor;
import me.uz.app.entity.User;
import me.uz.app.service.UserService;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    final UserService userService;

    @GetMapping("/me")
    public Mono<User> getUsers() {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(auth -> userService.findByUsername(auth.getName()));
    }
}
