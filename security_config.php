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
            'name' => 'secure_session',
            'lifetime' => 0,
            'path' => '/',
            'domain' => '', 
            // DÜZELTME: Localhost (HTTP) ise false, HTTPS ise true olur.
            'secure' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
            'httponly' => true,
            'samesite' => 'Lax',
            'regenerate_seconds' => 900,
            'idle_timeout_seconds' => 0,
            // DÜZELTME: Localhost'ta __Host- prefix çalışmaz, boş bırakıyoruz.
            'cookie_prefix' => '', 
        ],
        'csrf' => [
            'token_length' => 32,
            'lifetime' => 7200,
        ],
        'vault' => [
            'key' => 'eff9ff5e82def6e985f1888ad6965d44',
            'cipher' => 'AES-256-CBC',
            'iv' => '4e32b6c1c09a3445',
        ],
        'rate_limiting' => [
            'login_attempts' => 5,
            'login_window' => 300,
            'api_requests' => 100,
            'api_window' => 60,
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
?>