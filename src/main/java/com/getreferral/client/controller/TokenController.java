package com.getreferral.client.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Map;


@RestController
public class TokenController {


    @GetMapping("/session-token")
    public String getSessionToken(HttpSession session) {
        String token = (String) session.getAttribute("AUTH_TOKEN");
        if (token == null) {
            return "No token found in session";
        }
        return "Session Token: " + token;
    }




    private boolean isTokenExpired(String token) {
        // Logic to check token expiry (e.g., decode the JWT and check expiry time)
        return false; // Assume expired for demonstration
    }

    private String refreshToken(String refreshToken) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", "auth2");
        params.add("client_secret", "YsaoDpeMGvMTGwYlgQHV445pN6paDSaZ");
        params.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:8081/realms/dev/protocol/openid-connect/token",
                request,
                Map.class
        );

        return response.getBody().get("access_token").toString();
    }
}
