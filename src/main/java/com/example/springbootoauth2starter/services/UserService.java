package com.example.springbootoauth2starter.services;

import com.example.springbootoauth2starter.models.Provider;
import com.example.springbootoauth2starter.models.User;
import com.example.springbootoauth2starter.repositories.UserRepository;
import com.example.springbootoauth2starter.security.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repo;

    public void processOAuthPostLogin(CustomOAuth2User oauthUser, String registrationId) {
        User user = repo.getUserByUsername(oauthUser.getEmail());

        if (user == null) {
            user = new User();
            user.setRole("ROLE_USER");
            user.setProvider(registrationId.equals("google")
                    ? Provider.GOOGLE
                    : Provider.GITHUB);
            user.setFullName(oauthUser.getName());
            user.setUsername(oauthUser.getEmail());

            repo.save(user);
        }

    }

}