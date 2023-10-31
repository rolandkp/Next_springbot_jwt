# Next_springbot_jwt
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtility {
    private String secret = "yourSecretKey";
    private long validityInMilliseconds = 3600000; // 1 hour

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, secret)
            .compact();
    }

    public Boolean isTokenExpired(String token) {
        final Date expiration = extractExpiration(token);
        return expiration.before(new Date());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    public String refreshToken(String token) {
        if (isTokenExpired(token)) {
            final String username = extractUsername(token);
            UserDetails userDetails = yourUserDetailsService.loadUserByUsername(username);
            return generateToken(userDetails);
        }
        return token;
    }
}



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/refresh")
public class RefreshController {
    @Autowired
    private JwtUtility jwtUtility;

    @PostMapping
    public ResponseEntity<?> refreshAuthenticationToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        String oldToken = authorizationHeader.substring(7); // Remove "Bearer " prefix

        String refreshedToken = jwtUtility.refreshToken(oldToken);

        if (refreshedToken != null) {
            return ResponseEntity.ok(refreshedToken);
        } else {
            // Handle token refresh failure
            return ResponseEntity.badRequest().body("Token refresh failed.");
        }
    }
}


// axiosInstance.js

import axios from 'axios';

const apiUrl = 'http://localhost:8080'; // Replace with your server URL

const axiosInstance = axios.create({
  baseURL: apiUrl,
});

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response && error.response.status === 401) {
      const rememberMe = localStorage.getItem('rememberMe') === 'true';

      if (rememberMe) {
        // Handle token refresh here
        try {
          const response = await axiosInstance.post(`${apiUrl}/api/refresh`, null, {
            headers: { Authorization: `Bearer ${localStorage.getItem('jwtToken')}` },
          });
          const newToken = response.data;
          localStorage.setItem('jwtToken', newToken);
          error.config.headers.Authorization = `Bearer ${newToken}`;
          return axiosInstance(error.config);
        } catch (refreshError) {
          console.error('Token refresh error:', refreshError);
          // Handle token refresh error (e.g., log out the user)
          // Redirect to the login page or handle the logout process here
          window.location.href = '/login'; // Example: Redirect to the login page
        }
      } else {
        // Handle the case where "Remember Me" is set to false
        // Log out the user and redirect to the login page
        console.error('User logged out due to "Remember Me" set to false');
        localStorage.removeItem('jwtToken');
        window.location.href = '/login'; // Redirect to the login page
      }
    }
    return Promise.reject(error);
  }
);

export default axiosInstance;




#react








// src/axiosInstance.js

import axios from 'axios';

const apiUrl = 'http://localhost:8080'; // Replace with your server URL

const axiosInstance = axios.create({
  baseURL: apiUrl,
});

axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('jwtToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// A flag to prevent multiple token refresh requests
let isRefreshing = false;
let refreshSubscribers = [];

// Add a response interceptor to handle token refresh
axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    const originalRequest = error.config;

    if (error.response.status === 401) {
      if (!isRefreshing) {
        isRefreshing = true;

        // Make a request to refresh the token
        return refreshToken()
          .then((newToken) => {
            // Update the original request with the new token
            originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
            originalRequest.baseURL = '';
            axiosInstance.defaults.headers['Authorization'] = `Bearer ${newToken}`;
            refreshSubscribers = [];

            // Retry the original request
            return axiosInstance(originalRequest);
          })
          .catch((refreshError) => {
            // Handle token refresh error, e.g., log out the user
            console.error('Token refresh error:', refreshError);
            // Redirect to the login page or handle the logout process here
            window.location.href = '/login'; // Example: Redirect to the login page
          })
          .finally(() => {
            isRefreshing = false;
          });
      } else {
        // Create a promise to wait for token refresh
        return new Promise((resolve) => {
          // Add the request to the subscribers list
          refreshSubscribers.push((newToken) => {
            originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
            resolve(axiosInstance(originalRequest));
          });
        });
      }
    }
    return Promise.reject(error);
  }
);

// Function to refresh the token
function refreshToken() {
  const token = localStorage.getItem('jwtToken');

  // Implement your token refresh logic here, e.g., send a request to your server
  return axios.post(`${apiUrl}/api/refresh`, null, {
    headers: { Authorization: `Bearer ${token}` },
  })
    .then((response) => {
      const newToken = response.data;
      localStorage.setItem('jwtToken', newToken);

      // Notify all subscribers with the new token
      refreshSubscribers.forEach((callback) => callback(newToken));
      return newToken;
    });
}

export default axiosInstance;





