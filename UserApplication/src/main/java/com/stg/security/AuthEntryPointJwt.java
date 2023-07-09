package com.stg.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    public void commence(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response,
            AuthenticationException authException) throws IOException, jakarta.servlet.ServletException  {
        logger.error("Unauthorized error: {}", authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
        response.setContentType("application/json");
        response.getWriter().write("Error: Unauthorized");
    }
    
    private String getErrorMessageForStatusCode(int statusCode) {
        switch (statusCode) {
            case HttpServletResponse.SC_UNAUTHORIZED:
                return "Error: Unauthorized";
            case HttpServletResponse.SC_FORBIDDEN:
                return "Error: Forbidden";
            case HttpServletResponse.SC_NOT_FOUND:
                return "Error: Not Found";
            case HttpServletResponse.SC_BAD_REQUEST:
                return "Error: Bad Request";
            case HttpServletResponse.SC_INTERNAL_SERVER_ERROR:
                return "Error: Internal Server Error";
            case HttpServletResponse.SC_METHOD_NOT_ALLOWED:
                return "Error: Method Not Allowed";
            case HttpServletResponse.SC_CONFLICT:
                return "Error: Conflict";
            case HttpServletResponse.SC_PRECONDITION_FAILED:
                return "Error: Precondition Failed";
            case HttpServletResponse.SC_SERVICE_UNAVAILABLE:
                return "Error: Service Unavailable";
            case HttpServletResponse.SC_REQUEST_TIMEOUT:
                return "Error: Request Timeout";
            case HttpServletResponse.SC_GATEWAY_TIMEOUT:
                return "Error: Gateway Timeout";
            case HttpServletResponse.SC_NOT_IMPLEMENTED:
                return "Error: Not Implemented";
            case HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE:
                return "Error: Unsupported Media Type";
            // Add more cases for other status codes as needed
            default:
                return "Error: Unknown";
        }
    }


	

	
}
