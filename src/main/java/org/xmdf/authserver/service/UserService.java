package org.xmdf.authserver.service;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;
import org.xmdf.authserver.domain.Role;
import org.xmdf.authserver.domain.User;
import org.xmdf.authserver.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class UserService implements UserDetailsManager {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextHolderStrategy securityContextHolderStrategy;
    private final Map<String, Role> roleCache;

    public UserService(UserRepository userRepository, AuthenticationManager authenticationManager) {
        Assert.notNull(userRepository, "userRepository cannot be null");
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");

        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.securityContextHolderStrategy = SecurityContextHolder
                .getContextHolderStrategy();

        // This cache is safe to use this way as there is no way to create roles in the server,
        // however is not the best way at will cause problems if a role is inserted in the database directly.
        // Would also need to be updated in case the server allowed to manage roles directly.
        // In case
        this.roleCache = userRepository.getAllRoles().stream()
                .collect(Collectors.toMap(Role::getName, data -> data));
    }

    @Override
    public void createUser(UserDetails user) {
        userRepository.save(User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .enabled(true)
                .authorities(getEntityRoles(user))
                .build());
    }

    @Override
    public void updateUser(UserDetails user) {
        User databaseUser = getUser(user.getUsername());
        databaseUser.setUsername(user.getUsername());
        databaseUser.setEnabled(user.isEnabled());
        databaseUser.setAuthorities(getEntityRoles(user));

        userRepository.save(databaseUser);
    }

    @Override
    public void deleteUser(String username) {
        this.userRepository.delete(getUser(username));
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = this.securityContextHolderStrategy.getContext().getAuthentication();

        if (currentUser == null) {
            throw new AccessDeniedException(
                    "Can't change password as no Authentication object found in context " + "for current user.");
        }
        String username = currentUser.getName();

        if (this.authenticationManager != null) {
            this.authenticationManager
                    .authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, oldPassword));
        }

        User databaseUser = getUser(username);
        databaseUser.setPassword(newPassword);
        userRepository.save(databaseUser);

        Authentication authentication = createNewAuthentication(currentUser, newPassword);
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        this.securityContextHolderStrategy.setContext(context);
    }

    @Override
    public boolean userExists(String username) {
        return this.userRepository.existsByUsername(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return getUser(username);
    }

    protected Authentication createNewAuthentication(Authentication currentAuth, String newPassword) {
        UserDetails user = loadUserByUsername(currentAuth.getName());
        UsernamePasswordAuthenticationToken newAuthentication = UsernamePasswordAuthenticationToken.authenticated(user,
                null, user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());
        return newAuthentication;
    }

    private User getUser(String username) {
        return this.userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    private List<Role> getEntityRoles(UserDetails details) {
        return details.getAuthorities() == null
                ? new ArrayList<>()
                : details.getAuthorities().stream()
                .map(authority -> this.roleCache.get(authority.getAuthority()))
                .toList();
    }
}
