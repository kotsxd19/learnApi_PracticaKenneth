package IntegracionBackFront.backfront.Controller.Auth;

import IntegracionBackFront.backfront.Entities.Users.UserEntity;
import IntegracionBackFront.backfront.Models.DTO.Users.UserDTO;
import IntegracionBackFront.backfront.Services.Auth.AuthService;
import IntegracionBackFront.backfront.Utils.JWTUtils;
import jakarta.servlet.http.Cookie;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

@Autowired
    private AuthService service;

@Autowired
    private JWTUtils jwtUtils;


@PostMapping("/login")
private ResponseEntity<String> Login(@Valid @RequestBody UserDTO data, HttpServletResponse response){
    if (data.getCorreo() == null || data.getCorreo().isBlank() ||
            data.getContrasena() == null || data.getContrasena().isBlank()) {
        return ResponseEntity.status(401).body("Error: Credenciales incompletas");
    }

    if (service.login(data.getCorreo(), data.getContrasena())){
        addTokenCookie(response, data.getCorreo());
        return ResponseEntity.ok("Inicio de sesion exitosa");
    }
    return ResponseEntity.status(401).body("Credenciales Incorretas");
}

    private void addTokenCookie(HttpServletResponse response, String correo) {
        // Obtener el usuario completo de la base de datos
        Optional<UserEntity> userOpt = service.obtenerUsuario(correo);

        if (userOpt.isPresent()) {
            UserEntity user = userOpt.get();
            String token = jwtUtils.create(
                    String.valueOf(user.getId()),
                    user.getCorreo(),
                    user.getTipoUsuario().getNombreTipo() // ← Usar el nombre real del tipo
            );

            Cookie cookie = new Cookie("authToken", token);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(86400);
            response.addCookie(cookie);
        }
    }
}
