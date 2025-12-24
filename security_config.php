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
            'key' => 'eff9ff5e82def6e985f1888ad6965d44',
            'cipher' => 'AES-256-CBC',
            'iv' => '4e32b6c1c09a3445',
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
