package com.example.springbootoauth2starter.services;

import com.example.springbootoauth2starter.models.Provider;
import com.example.springbootoauth2starter.models.User;
import com.example.springbootoauth2starter.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repo;

    public void processOAuthPostLogin(String fullName, String username) {
        User existUser = repo.getUserByUsername(username);

        if (existUser == null) {
            User newUser = new User();
            newUser.setRole("ROLE_USER");
            newUser.setFullName(fullName);
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEnabled(true);

            repo.save(newUser);
        }

    }

}