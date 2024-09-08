package baykov.daniel.cookie_auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "token_types")
public class TokenType extends BaseEntity {

    @Column(nullable = false, unique = true)
    @Enumerated(EnumType.STRING)
    private TokenTypeEnum name;

    @Getter
    public enum TokenTypeEnum {
        ACCESS("access-token"),
        CONFIRMATION("confirmation-token"),
        VERIFICATION("verification-token"),
        RESET("reset-token");

        private final String value;

        TokenTypeEnum(String value) {
            this.value = value;
        }
    }
}
