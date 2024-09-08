package baykov.daniel.cookie_auth.model.base;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.validation.FieldError;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class StatusFieldError {

    private FieldError fieldError;

    public String getObjectName() {
        return fieldError.getObjectName();
    }

    public String getField() {
        return fieldError.getField();
    }

    public String getRejectedValue() {
        return fieldError.getRejectedValue() == null ? null : fieldError.getRejectedValue().toString();
    }

    public String getCode() {
        return fieldError.getCode();
    }

    public String[] getCodes() {
        return fieldError.getCodes();
    }

    public String getDefaultMessage() {
        return fieldError.getDefaultMessage();
    }
}
