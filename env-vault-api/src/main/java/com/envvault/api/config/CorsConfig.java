package com.envvault.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Global CORS configuration.
 *
 * <p>The production origin is read from the {@code CORS_ALLOWED_ORIGIN} environment
 * variable and falls back to a placeholder until the real GitHub Pages URL is known.
 * Local development origins are always allowed.
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${CORS_ALLOWED_ORIGIN:https://placeholder.github.io}")
    private String productionOrigin;

    /**
     * Local development origins. These are only needed when running the frontend
     * from a local static server — remove or disable them once the site is live.
     */
    private static final String[] LOCAL_DEV_ORIGINS = {
            "http://localhost:5500",
            "http://127.0.0.1:5500",
            "http://localhost:3000"
    };

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // Production origin (from CORS_ALLOWED_ORIGIN) plus the local-dev origins above.
        String[] allowedOrigins = new String[LOCAL_DEV_ORIGINS.length + 1];
        allowedOrigins[0] = productionOrigin;
        System.arraycopy(LOCAL_DEV_ORIGINS, 0, allowedOrigins, 1, LOCAL_DEV_ORIGINS.length);

        registry.addMapping("/api/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods("GET", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
