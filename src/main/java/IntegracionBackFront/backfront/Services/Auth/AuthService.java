package IntegracionBackFront.backfront.Services.Auth;

import IntegracionBackFront.backfront.Config.Argon2.Argon2Password;
import IntegracionBackFront.backfront.Entities.Users.UserEntity;
import IntegracionBackFront.backfront.Repositories.Users.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository repo;

    public boolean login(String correo,  String contrasena){
        Argon2Password objHash = new Argon2Password();
        Optional<UserEntity> List = repo.findByCorreo(correo).stream().findFirst();
        if (List.isPresent()){
            UserEntity usuario = List.get();
            String nombreTipoUsuario = usuario.getTipoUsuario().getNombreTipo();
            System.out.println("Usuario ID encontrado: " + usuario.getId() +
                    ",email: " + usuario.getCorreo() +
                    ",rol: " + nombreTipoUsuario);
            return objHash.VerifyPassword(usuario.getContrasena(),contrasena);
        }
        return false;
    }


    public Optional<UserEntity> obtenerUsuario(String email){
        Optional<UserEntity> userOpt = repo.findByCorreo(email);
        return (userOpt != null) ? userOpt : null;
    }


}
