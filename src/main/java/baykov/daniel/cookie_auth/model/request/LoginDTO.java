package baykov.daniel.cookie_auth.model.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class LoginDTO {

    @NotEmpty(message = "Email should not be null or empty")
    private String email;

    @NotEmpty(message = "Password should not be null or empty")
    private String password;
}
