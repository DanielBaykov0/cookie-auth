package baykov.daniel.cookie_auth.initializer;

import baykov.daniel.cookie_auth.entity.Role;
import baykov.daniel.cookie_auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class RoleInitializer {

    private final RoleRepository roleRepository;

    @EventListener
    @Transactional
    public void onApplicationReady(ApplicationReadyEvent event) {
        for (Role.RoleEnum roleEnum : Role.RoleEnum.values()) {
            if (!roleRepository.existsByName(roleEnum)) {
                Role role = new Role();
                role.setName(roleEnum);
                roleRepository.save(role);
            }
        }
    }
}
