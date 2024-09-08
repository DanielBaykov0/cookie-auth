package baykov.daniel.cookie_auth.model.base;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.validation.ObjectError;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class StatusObjectError {

    private ObjectError objectError;

    public String getObjectName() {
        return objectError.getObjectName();
    }

    public String getCode() {
        return objectError.getCode();
    }

    public String[] getCodes() {
        return objectError.getCodes();
    }

    public String getDefaultMessage() {
        return objectError.getDefaultMessage();
    }
}
