package com.getreferral.client.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

@Controller
public class HomeController {

    private RestTemplate restTemplate=new RestTemplate();

    @GetMapping("/")
    public String home() {
        return "home"; // Corresponds to home.html in templates
    }

    @GetMapping("/login-success")
    public String loginSuccess(@RequestParam("code") String authorizationCode, HttpSession session) {
        // Keycloak token endpoint
        String tokenUri = "http://localhost:8081/realms/dev/protocol/openid-connect/token";

        // Prepare the request body
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", authorizationCode);
        params.add("redirect_uri", "http://127.0.0.1:8082/login-success");
        params.add("client_id", "auth2");
        params.add("client_secret", "YsaoDpeMGvMTGwYlgQHV445pN6paDSaZ");

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Make the POST request to Keycloak
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.exchange(tokenUri, HttpMethod.POST, request, Map.class);

        // Extract the response data
        Map<String, Object> tokenResponse = response.getBody();
        if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
            // Handle failure (e.g., token not received)
            return "redirect:/";  // Redirect to home if there's an error
        }

        // Save tokens and response data in the session
        session.setAttribute("access_token", tokenResponse.get("access_token"));
        session.setAttribute("refresh_token", tokenResponse.get("refresh_token"));
        session.setAttribute("id_token", tokenResponse.get("id_token"));
        session.setAttribute("token_response", tokenResponse);

        // Redirect to access-resource
        return "redirect:/access-resource";  // Redirect instead of rendering a template
    }




    @GetMapping("/access-resource")
    public ResponseEntity<String> accessResource(HttpSession session) {
        // Retrieve the access token from the session
        String accessToken = (String) session.getAttribute("access_token");

        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Access token not found. Please log in again.");
        }

        // Resource server URL
        String resourceUrl = "http://127.0.0.1:8080/api/v1/home";

        // Set Authorization header with the Bearer token
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            // Make the GET request to the resource server
            ResponseEntity<String> response = restTemplate.exchange(resourceUrl, HttpMethod.GET, request, String.class);
            return response;
        } catch (HttpClientErrorException e) {
            // Handle 401 or 403 errors
            return ResponseEntity.status(e.getStatusCode()).body("Access denied: " + e.getMessage());
        }
    }



}
