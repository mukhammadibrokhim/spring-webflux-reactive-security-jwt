package me.uz.app.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Table("users")
public class User {
    @Id
    private Long id;
    private String username;
    private String password;
    private List<String> roles = new ArrayList<>();
//    @MappedCollection(idColumn = "user_id")
//    private Set<UserRole> roles;
}
