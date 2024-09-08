package baykov.daniel.cookie_auth.model.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RegisterDTO {

    private String fullName;

    @NotEmpty(message = "Email should not be null or empty")
    private String email;

    @NotEmpty(message = "Password should not be null or empty")
    private String password;

    @NotEmpty(message = "Matching Password should not be null or empty")
    private String matchingPassword;

    @NotNull(message = "GDPR should not be null.")
    @AssertTrue(message = "GDPR Should be accepted!")
    private Boolean euGDPR;
}
