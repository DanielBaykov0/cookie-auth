package baykov.daniel.cookie_auth.model.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ChangePasswordDTO {

    @NotEmpty(message = "Password should not be null or empty")
    String password;

    @NotEmpty(message = "Matching Password should not be null or empty")
    String matchingPassword;
}
