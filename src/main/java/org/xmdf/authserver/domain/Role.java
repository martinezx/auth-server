package org.xmdf.authserver.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity(name = "role")
@Table(name = "_role")
public class Role implements GrantedAuthority {

    @Id
    private UUID id;
    private String name;

    @Override
    public String getAuthority() {
        return name;
    }
}
