package baykov.daniel.cookie_auth.security;

import baykov.daniel.cookie_auth.model.base.StatusMessageException;
import baykov.daniel.cookie_auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

import static baykov.daniel.cookie_auth.constant.ErrorMessages.USER_NOT_FOUND_BY_EMAIL;
import static baykov.daniel.cookie_auth.constant.ErrorMessages.USER_NOT_FOUND_BY_EMAIL_ERR;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        var user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> StatusMessageException.error(USER_NOT_FOUND_BY_EMAIL_ERR, USER_NOT_FOUND_BY_EMAIL + email));

        Set<GrantedAuthority> authorities = user
                .getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority((role.getName().toString())))
                .collect(Collectors.toSet());
        return new User(user.getEmail(), user.getPassword(), authorities);
    }
}
