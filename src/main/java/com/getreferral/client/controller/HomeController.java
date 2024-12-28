package com.getreferral.client.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Map;

@Controller
public class HomeController {

    private RestTemplate restTemplate=new RestTemplate();

    @GetMapping("/")
    public String home() {
        return "home"; // Corresponds to home.html in templates
    }

    @GetMapping("/login-success")
    public String loginSuccess(@RequestParam("code") String authorizationCode, HttpSession session , HttpServletResponse response) {
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
        ResponseEntity<Map> responseEntity = restTemplate.exchange(tokenUri, HttpMethod.POST, request, Map.class);

        // Extract the response data
        Map<String, Object> tokenResponse = responseEntity.getBody();
        if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
            // Handle failure (e.g., token not received)
            return "redirect:/";  // Redirect to home if there's an error
        }

        // Save tokens and response data in the session
        session.setAttribute("access_token", tokenResponse.get("access_token"));
        session.setAttribute("refresh_token", tokenResponse.get("refresh_token"));
        session.setAttribute("id_token", tokenResponse.get("id_token"));
        session.setAttribute("token_response", tokenResponse);

        // Create a cookie for the session ID
        Cookie sessionCookie = new Cookie("SESSIONID", session.getId()); // Use session ID as the cookie value
        sessionCookie.setHttpOnly(true); // Prevent access from JavaScript
        sessionCookie.setPath("/"); // Make the cookie accessible for all paths on the current domain
        sessionCookie.setMaxAge(60 * 60 * 24 * 15 );// Optional: Set expiration time (e.g., 1 hour
        response.addCookie(sessionCookie); // Add the cookie to the response

        // Redirect to access-resource
        return "redirect:/access-resource";  // Redirect instead of rendering a template
    }




    @GetMapping("/access-resource")
    public ResponseEntity<String> accessResource(HttpSession session) {

        // Retrieve tokens from session
        String accessToken = (String) session.getAttribute("access_token");
        String refreshToken = (String) session.getAttribute("refresh_token");

        // Check if access token is valid (not expired)
        if (accessToken == null || isTokenExpired(accessToken)) {
            // If refresh token is also invalid, redirect to home page
            if (refreshToken == null || isTokenExpired(refreshToken)) {
                return ResponseEntity.status(HttpStatus.FOUND).header("Location", "/").build();
            }

            // Use refresh token to get a new access token
            try {
                Map<String, Object> newTokens = getNewTokensUsingRefreshToken(refreshToken);

                // Update tokens in session
                accessToken = (String) newTokens.get("access_token");
                session.setAttribute("access_token", accessToken);

                // Update refresh token if provided
                if (newTokens.containsKey("refresh_token")) {
                    session.setAttribute("refresh_token", newTokens.get("refresh_token"));
                }
            } catch (Exception e) {
                // Redirect to home page if refreshing the token fails
                return ResponseEntity.status(HttpStatus.FOUND).header("Location", "/").build();
            }
        }

        // Access the resource server with the valid access token
        String resourceUrl = "http://127.0.0.1:8080/api/v1/home";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            // Make the GET request to the resource server
            ResponseEntity<String> resourceResponse = restTemplate.exchange(resourceUrl, HttpMethod.GET, request, String.class);
            return resourceResponse;
        } catch (HttpClientErrorException e) {
            // Handle 401 or 403 errors
            return ResponseEntity.status(e.getStatusCode()).body("Access denied: " + e.getMessage());
        } catch (ResourceAccessException e) {
            // Handle server down or connection issues
            return ResponseEntity.status(HttpStatus.FOUND).header("Location", "/").build(); // Redirect to home page
        } catch (Exception e) {
            // Handle other unexpected exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + e.getMessage());
        }
    }


    private boolean isTokenExpired(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return true; // Invalid token format
            }
            String payload = new String(Base64.getDecoder().decode(parts[1]));
            Map<String, Object> claims = new ObjectMapper().readValue(payload, Map.class);
            long exp = (Integer) claims.get("exp"); // Extract "exp" claim
            return exp * 1000 < System.currentTimeMillis(); // Check if expired
        } catch (Exception e) {
            return true; // Assume expired on error
        }
    }

    private Map<String, Object> getNewTokensUsingRefreshToken(String refreshToken) throws Exception {
        String tokenUri = "http://localhost:8081/realms/dev/protocol/openid-connect/token";

        // Prepare the request body
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);
        params.add("client_id", "auth2");
        params.add("client_secret", "YsaoDpeMGvMTGwYlgQHV445pN6paDSaZ");

        // Set headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Make the POST request to Keycloak
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.exchange(tokenUri, HttpMethod.POST, request, Map.class);

        if (response.getBody() == null || !response.getBody().containsKey("access_token")) {
            throw new Exception("Failed to refresh tokens.");
        }

        return response.getBody();
    }






}
