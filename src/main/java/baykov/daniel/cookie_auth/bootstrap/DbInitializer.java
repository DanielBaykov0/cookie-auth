package baykov.daniel.cookie_auth.bootstrap;

import baykov.daniel.cookie_auth.entity.Role;
import baykov.daniel.cookie_auth.entity.TokenType;
import baykov.daniel.cookie_auth.repository.RoleRepository;
import baykov.daniel.cookie_auth.repository.TokenTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DbInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final TokenTypeRepository tokenTypeRepository;

    @Override
    public void run(String... args) {
        initializeRoles();
        initializeTokens();
    }

    private void initializeRoles() {
        if (roleRepository.count() == 0) {
            for (Role.RoleEnum roleEnum : Role.RoleEnum.values()) {
//            if (!roleRepository.existsByName(roleEnum)) {
                Role role = new Role();
                role.setName(roleEnum);
                roleRepository.save(role);
//            }
            }
        }
    }

    private void initializeTokens() {
        if (tokenTypeRepository.count() == 0) {
            for (TokenType.TokenTypeEnum tokenTypeEnum : TokenType.TokenTypeEnum.values()) {
                TokenType tokenType = new TokenType();
                tokenType.setName(tokenTypeEnum);
                tokenTypeRepository.save(tokenType);
            }
        }
    }
}
