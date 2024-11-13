package org.xmdf.authserver.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.UUID;

import static lombok.EqualsAndHashCode.Include;

@Data
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = "role")
@Table(name = "_role")
public class Role implements GrantedAuthority {

    @Id
    @Include
    private UUID id;
    @Column(unique = true, length = 100)
    private String name;

    @Override
    public String getAuthority() {
        return name;
    }
}
