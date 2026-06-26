package com.envvault.api.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Serves the client-side secret-scanning ruleset.
 *
 * <p>This controller only reads a static, bundled ruleset from the classpath. It never
 * accepts, processes, or logs any {@code .env} content — all scanning happens in the browser.
 */
@RestController
@RequestMapping("/api")
public class RulesetController {

    private final JsonNode rules;

    public RulesetController(ResourceLoader resourceLoader, ObjectMapper objectMapper) throws IOException {
        Resource resource = resourceLoader.getResource("classpath:rules.json");
        try (InputStream in = resource.getInputStream()) {
            this.rules = objectMapper.readTree(in);
        }
    }

    /**
     * Returns the full ruleset as a JSON array. Cacheable for 24 hours since rules
     * change infrequently and contain no user data.
     */
    @GetMapping(value = "/rules", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> getRules() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(86400, TimeUnit.SECONDS).cachePublic())
                .body(rules);
    }

    /**
     * Lightweight health endpoint used for keep-alive pinging on free-tier hosting.
     */
    @GetMapping(value = "/ping", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> ping() {
        return Map.of("status", "ok");
    }
}
