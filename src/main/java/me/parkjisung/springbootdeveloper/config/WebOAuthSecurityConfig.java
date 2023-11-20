package me.parkjisung.springbootdeveloper.config;

import lombok.RequiredArgsConstructor;
import me.parkjisung.springbootdeveloper.config.jwt.TokenProvider;
import me.parkjisung.springbootdeveloper.config.oauth.OAuth2AuthorizationRequestBasedOnCookieRepository;
import me.parkjisung.springbootdeveloper.config.oauth.OAuth2SuccessHandler;
import me.parkjisung.springbootdeveloper.config.oauth.OAuth2UserCustomService;
import me.parkjisung.springbootdeveloper.repository.RefreshTokenRepository;
import me.parkjisung.springbootdeveloper.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
public class WebOAuthSecurityConfig {

    // OAuth2UserCustomService, TokenProvider 등을 주입받는 생성자
    private final OAuth2UserCustomService oAuth2UserCustomService;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;

    // 정적 자원 및 H2 콘솔 관련 설정
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
//                .requestMatchers(toH2Console())
                .requestMatchers("/img/**", "/css/**", "/js/**");
    }

    // 보안 필터 체인 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF, 기본 HTTP 인증, 폼 로그인, 로그아웃 설정 비활성화. security6 형식으로 작성.
        http.csrf(csrf -> csrf.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(formLogin -> formLogin.disable())
                .logout(logout -> logout.disable());

        // 세션 관리 정책을 STATELESS로 설정
        // Stateless 세션 관리는 세션 정보를 서버에 저장하지 않고, 클라이언트가 필요한 정보를 모든 요청에 함께 제공하도록 함.
        // 이로써 서버 측에서 세션 관리와 관련된 공격(예: 세션 하이재킹)을 방지할 수 있음.
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 토큰 인증 필터 추가
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        // API 엔드포인트 권한 설정
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(new AntPathRequestMatcher("/api/token")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/api/**")).authenticated()
                .anyRequest().permitAll());

        // OAuth2 로그인 설정
        http
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .authorizationEndpoint(authorization -> authorization
                                // 권한 요청 저장소 설정: 인증 요청 및 권한 부여 코드를 저장하는 방법을 지정.
                                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())
                        )
                        // OAuth2 로그인 성공 핸들러 설정: 로그인 성공 시 실행할 추가 작업을 정의.
                        .successHandler(oAuth2SuccessHandler())
                        .userInfoEndpoint(userInfo -> userInfo
                                // 사용자 정보 서비스 설정: OAuth2 로그인 후 사용자 정보를 가져오는 서비스를 지정.
                                .userService(oAuth2UserCustomService)
                        )
                ).logout(logout -> logout
                        .logoutSuccessUrl("/login")
                ).exceptionHandling(exception -> exception
                        // 기본 인증 진입 지점 설정: 인증되지 않은 사용자에 대한 기본 처리 방식을 지정합니다.
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),  // HTTP 401 상태 코드로 응답
                                new AntPathRequestMatcher("/api/**")  // 특정 패턴의 요청에 대한 처리를 설정.
                                // 여기서는 "/api/**" 패턴의 요청에 대해 인증되지 않은 경우 401 상태 코드로 응답하도록 설정.
                        )
                );

        return http.build();
    }

    // OAuth2 로그인 성공 핸들러 빈
    @Bean
    public OAuth2SuccessHandler oAuth2SuccessHandler() {
        return new OAuth2SuccessHandler(tokenProvider,
                refreshTokenRepository,
                oAuth2AuthorizationRequestBasedOnCookieRepository(),
                userService
        );
    }

    // 토큰 인증 필터 빈
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }

    // OAuth2 인증 요청을 쿠키 기반으로 처리하는 레포지토리 빈
    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    // BCryptPasswordEncoder 빈
    // 사용자 비밀번호를 안전하게 저장하고 검증
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
