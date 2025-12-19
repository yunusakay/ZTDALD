<?php

final class SecurityHelper
{
    private static array $cfg;

    /**
     * Apply security headers to the response
     */
    private static function applySecurityHeaders(): void
    {
        // Security Headers
        $headers = [
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Content-Security-Policy' => "default-src 'self'; " .
                                      "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
                                      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
                                      "img-src 'self' data:; " .
                                      "connect-src 'self'; " .
                                      "frame-ancestors 'none'; " .
                                      "form-action 'self'; " .
                                      "base-uri 'self';",
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
            'X-Permitted-Cross-Domain-Policies' => 'none',
            'X-Download-Options' => 'noopen',
            'X-Powered-By' => 'None',
            'Permissions-Policy' => 'geolocation=(), microphone=(), camera=(), payment=()',
            'Cache-Control' => 'no-store, max-age=0',
            'Pragma' => 'no-cache',
            'Feature-Policy' => "geolocation 'none'; microphone 'none'; camera 'none'; payment 'none'"
        ];

        foreach ($headers as $header => $value) {
            header("$header: $value");
        }
    }

    public static function init(): void
    {
        self::$cfg = require __DIR__ . '/security_config.php';

        // Apply security headers first
        self::applySecurityHeaders();

        // Start secure session
        self::startSecureSession();

        // Set CSRF token if not exists
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes((int)(self::$cfg['security']['csrf']['token_length'] ?? 32)));
        }
        
        // Regenerate session ID periodically for security
        self::regenerateSessionPeriodically();
    }

    private static function startSecureSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $s = self::$cfg['security']['session'] ?? [];

        if (!empty($s['name'])) {
            session_name((string)$s['name']);
        }

        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

        session_set_cookie_params([
            'lifetime' => (int)($s['lifetime'] ?? 0),
            'path' => (string)($s['path'] ?? '/'),
            'domain' => (string)($s['domain'] ?? ''),
            'secure' => $secure,
            'httponly' => (bool)($s['httponly'] ?? true),
            'samesite' => (string)($s['samesite'] ?? 'Lax'),
        ]);

        session_start();

        if (!isset($_SESSION['__regen_ts'])) {
            session_regenerate_id(true);
            $_SESSION['__regen_ts'] = time();
        } else {
            $interval = (int)(self::$cfg['security']['session']['regenerate_seconds'] ?? 900);
            if ($interval > 0 && (time() - (int)$_SESSION['__regen_ts']) >= $interval) {
                session_regenerate_id(true);
                $_SESSION['__regen_ts'] = time();
            }
        }

        $idle = (int)(self::$cfg['security']['session']['idle_timeout_seconds'] ?? 1800);
        if (isset($_SESSION['__last_activity']) && $idle > 0) {
            if ((time() - (int)$_SESSION['__last_activity']) > $idle) {
                self::logout();
            }
        }
        $_SESSION['__last_activity'] = time();
    }

    /**
     * Regenerate session ID periodically to prevent session fixation
     */
    private static function regenerateSessionPeriodically(): void
    {
        $regenerateInterval = (int)(self::$cfg['security']['session']['regenerate_seconds'] ?? 900); // 15 minutes by default
        
        if (!isset($_SESSION['__last_regeneration'])) {
            session_regenerate_id(true);
            $_SESSION['__last_regeneration'] = time();
        } elseif ((time() - $_SESSION['__last_regeneration']) > $regenerateInterval) {
            // Preserve session data during regeneration
            $data = $_SESSION;
            session_regenerate_id(true);
            $_SESSION = $data;
            $_SESSION['__last_regeneration'] = time();
        }
    }

    /**
     * Validate input against common attack vectors
     */
    public static function validateInput($input, $type = 'string', $options = [])
    {
        if ($input === null) return null;

        $input = trim((string)$input);

        switch ($type) {
            case 'email':
                return filter_var($input, FILTER_VALIDATE_EMAIL) ? $input : null;

            case 'int':
                $min = $options['min'] ?? PHP_INT_MIN;
                $max = $options['max'] ?? PHP_INT_MAX;
                $options = [
                    'options' => [
                        'min_range' => $min,
                        'max_range' => $max
                    ]
                ];
                return filter_var($input, FILTER_VALIDATE_INT, $options);

            case 'alnum':
                return preg_match('/^[a-zA-Z0-9]+$/', $input) ? $input : null;

            case 'alnum_space':
                return preg_match('/^[a-zA-Z0-9\s]+$/', $input) ? $input : null;

            case 'username':
                return preg_match('/^[a-zA-Z0-9_\-\.@]+$/', $input) ? $input : null;

            case 'password':
                $minLength = $options['min_length'] ?? 8;
                if (strlen($input) < $minLength) return null;
                return $input;

            case 'string':
            default:
                // Basic XSS prevention
                $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

                // Check max length if specified
                if (isset($options['max_length']) && mb_strlen($input) > $options['max_length']) {
                    return mb_substr($input, 0, $options['max_length']);
                }

                return $input;
        }
    }

    /**
     * Validate and sanitize array of inputs
     */
    public static function validateInputs(array $inputs, array $rules)
    {
        $validated = [];
        $errors = [];

        foreach ($rules as $field => $rule) {
            $value = $inputs[$field] ?? null;
            $type = $rule['type'] ?? 'string';

            // Check required fields
            if (($rule['required'] ?? false) && ($value === null || $value === '')) {
                $errors[$field] = "$field is required";
                continue;
            }

            // Skip validation for empty non-required fields
            if (($value === null || $value === '') && !($rule['required'] ?? false)) {
                $validated[$field] = null;
                continue;
            }

            // Validate based on type
            $validatedValue = self::validateInput($value, $type, $rule);

            if ($validatedValue === null) {
                $errors[$field] = $rule['message'] ?? "Invalid value for $field";
            } else {
                $validated[$field] = $validatedValue;
            }
        }

        return [
            'data' => $validated,
            'errors' => $errors,
            'valid' => empty($errors)
        ];
    }

    public static function csrfToken(): string
    {
        return (string)($_SESSION['csrf_token'] ?? '');
    }

    public static function verifyCsrf(?string $token): bool
    {
        $sessionToken = (string)($_SESSION['csrf_token'] ?? '');
        if ($sessionToken === '' || $token === null) {
            return false;
        }
        return hash_equals($sessionToken, (string)$token);
    }

    public static function e(?string $value): string
    {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function rateLimited(string $key, int $limit, int $windowSeconds): bool
    {
        if ($limit <= 0 || $windowSeconds <= 0) {
            return false;
        }

        $now = time();
        $bucketKey = '__rl_' . $key;
        $bucket = $_SESSION[$bucketKey] ?? [];
        if (!is_array($bucket)) {
            $bucket = [];
        }

        $cutoff = $now - $windowSeconds;
        $bucket = array_values(array_filter($bucket, static fn($ts) => is_int($ts) && $ts > $cutoff));

        if (count($bucket) >= $limit) {
            $_SESSION[$bucketKey] = $bucket;
            return true;
        }

        $bucket[] = $now;
        $_SESSION[$bucketKey] = $bucket;
        return false;
    }

    public static function passwordIsHash(string $stored): bool
    {
        $info = password_get_info($stored);
        return isset($info['algo']) && $info['algo'] !== 0;
    }

    public static function passwordHash(string $password): string
    {
        $algo = self::$cfg['security']['password']['algo'] ?? PASSWORD_BCRYPT;
        $opts = self::$cfg['security']['password']['options'] ?? [];
        $hash = password_hash($password, $algo, is_array($opts) ? $opts : []);
        return $hash ?: '';
    }

    public static function logout(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'] ?? '/', $p['domain'] ?? '', (bool)($p['secure'] ?? false), (bool)($p['httponly'] ?? true));
        }
        session_destroy();
        header('Location: index.php');
        exit;
    }
}
