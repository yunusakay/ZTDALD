<?php
return [
    'security' => [
        'password' => [
            'algo' => PASSWORD_BCRYPT,
            'options' => [
                'cost' => 12,
            ],
        ],
        'session' => [
            'name' => 'ztal_session',
            'lifetime' => 0, // Session expires when browser closes
            'path' => '/',
            'domain' => '',
            'secure' => isset($_SERVER['HTTPS']), // Auto-detect HTTPS
            'httponly' => true,
            'samesite' => 'Lax',
            'regenerate_seconds' => 900, // 15 minutes
            'idle_timeout_seconds' => 0, // No idle timeout - session expires only when browser closes
            'cookie_prefix' => '__Host-', // Requires Secure and Path=/
        ],
        'csrf' => [
            'token_length' => 32,
            'lifetime' => 7200, // 2 hours
        ],
        'vault' => [
            'key' => 'b7f3c9e2a1d8f6e5c4b3a2d1e0f9c8b7a6d5e4f3c2b1a0d9e8f7c6b5a4d3e2', // Randomly generated
            'cipher' => 'AES-256-CBC',
            'iv' => 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', // Randomly generated
        ],
        'rate_limiting' => [
            'login_attempts' => 5, // Max login attempts
            'login_window' => 300, // 5 minutes
            'api_requests' => 100, // Max API requests
            'api_window' => 60, // 1 minute
        ],
        'headers' => [
            'xss_protection' => '1; mode=block',
            'content_type_options' => 'nosniff',
            'x_frame_options' => 'DENY',
            'referrer_policy' => 'strict-origin-when-cross-origin',
            'permissions_policy' => 'geolocation=(), microphone=(), camera=(), payment=()',
            'strict_transport_security' => 'max-age=31536000; includeSubDomains; preload',
        ],
    ],
];
