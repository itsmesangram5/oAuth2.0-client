package com.getreferral.client.utils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;


@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession();
        // Generate your token (e.g., JWT or custom token)
        String token = "GeneratedToken"; // Replace with actual token generation logic

        // Store token in the session
        session.setAttribute("AUTH_TOKEN", token);

        // Redirect to home page or a secured endpoint
        response.setStatus(HttpServletResponse.SC_OK);
    }
}

