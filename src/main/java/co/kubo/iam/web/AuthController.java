package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.TokenService;
import co.kubo.iam.application.dto.AuthDtos.LoginRequest;
import co.kubo.iam.application.dto.AuthDtos.LogoutRequest;
import co.kubo.iam.application.dto.AuthDtos.RefreshRequest;
import co.kubo.iam.application.dto.AuthDtos.RegisterRequest;
import co.kubo.iam.application.dto.AuthDtos.TokenResponse;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.InternalAuthFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    public AuthController(AuthService authService, TokenService tokenService) {
        this.authService = authService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public TokenResponse register(
            @Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        return authService.register(request, clientIp(http), http.getHeader("User-Agent"));
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return authService.login(request, clientIp(http), http.getHeader("User-Agent"));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(
            @Valid @RequestBody RefreshRequest request, HttpServletRequest http) {
        return authService.refresh(request, clientIp(http), http.getHeader("User-Agent"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public UserResponse me(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        return authService.me(userId);
    }

    /** Documento JWKS que el API Gateway usa para verificar la firma de los access tokens. */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks() {
        return ResponseEntity.ok(tokenService.jwks());
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
