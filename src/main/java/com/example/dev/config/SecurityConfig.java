package com.example.dev.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.dev.filter.JwtFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final JwtFilter jwtFilter;
	private final UserDetailsService userDetailsService;
	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

	public SecurityConfig(JwtFilter jwtFilter, UserDetailsService userDetailsService,
			JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
		this.jwtFilter = jwtFilter;
		this.userDetailsService = userDetailsService;
		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http
				.csrf(csrf -> csrf.disable())
				.cors(cors -> cors.configurationSource(request -> {
					var corsConfiguration = new org.springframework.web.cors.CorsConfiguration();
					corsConfiguration.setAllowedOrigins(java.util.List.of("*"));
					corsConfiguration.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
					corsConfiguration.setAllowedHeaders(java.util.List.of("*"));
					return corsConfiguration;
				}))
				.authorizeHttpRequests(auth -> auth

						// ✅ Allow HTML pages & static resources
						.requestMatchers(
								"/",
								"/login.html",
								"/dashboard.html",
								"/**/*.html",
								"/css/**",
								"/js/**",
								"/images/**")
						.permitAll()

						// ✅ Allow Auth & Public APIs
						.requestMatchers(
								"/auth/api/v1/login",
								"/user/api/v1/add",
								"/lead/api/v1/add",
								"/lead/api/v1/count")
						.permitAll()

						// ✅ Secure APIs (JWT required)
						.requestMatchers(
								"/lead/api/v1/get-leads",
								"/lead/api/v1/update",
								"/lead/api/v1/update-status",
								"/lead/api/v1/delete",
								"/api/users/**")
						.authenticated()

						// ✅ Any other request needs authentication
						.anyRequest().authenticated())
				.exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint))
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
			throws Exception {
		return config.getAuthenticationManager();
	}

}
