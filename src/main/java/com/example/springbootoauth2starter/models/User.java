package com.example.springbootoauth2starter.models;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "users")
@Getter
@Setter
public class User {
    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fullName;
    private String username;
    private String password;
    private String role;
    private boolean enabled;

    @Enumerated(EnumType.STRING)
    private Provider provider;

// getters and setters are not shown for brevity

}