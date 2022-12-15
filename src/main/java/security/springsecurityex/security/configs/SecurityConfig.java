package security.springsecurityex.security.configs;


import jakarta.websocket.Encoder;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import security.springsecurityex.security.service.CustomUserDetailsService;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    /**
     * 메모리 방식의 사용자 등록
     */
//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
//        String password = passwordEncoder().encode("1234");
//
//        AuthenticationManagerBuilder auth = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");
//
//        return auth.build();
//    }

    /**
     * Custom한 userDetailService를 사용하도록 함
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {

        AuthenticationManagerBuilder auth = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
        auth.userDetailsService(userDetailsService);

        return auth.build();
    }

    /**
     * 정적 파일에 대해서는 security 필터들을 거치지 않고 서빙하도록
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests()
                .requestMatchers("/", "/users").permitAll()
                .requestMatchers("/mypage").hasRole("USER")
                .requestMatchers("/messages").hasRole("MANAGER")
                .requestMatchers("/config").hasRole("ADMIN")
                .anyRequest()
                .authenticated()

                .and()
                .formLogin();

        return http.build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


}
