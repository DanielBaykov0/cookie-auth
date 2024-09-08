package baykov.daniel.cookie_auth.model.request;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class VerificationRequestDTO {

    private String code;
}
