<?php

final class SecurityHelper
{
    private static array $cfg;

    private static function applySecurityHeaders(): void
    {
        $headers = [
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
            'X-XSS-Protection' => '1; mode=block',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;",
            'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload'
        ];

        foreach ($headers as $header => $value) {
            header("$header: $value");
        }
    }

    public static function init(): void
    {
        self::$cfg = require __DIR__ . '/security_config.php';
        self::applySecurityHeaders();
        self::startSecureSession();

        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        
        self::regenerateSessionPeriodically();
    }

    private static function startSecureSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) return;

        $s = self::$cfg['security']['session'] ?? [];
        session_name($s['name'] ?? 'secure_session');
        
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        session_start();
    }

    public static function regenerateSessionPeriodically(): void
    {
        // Regenerate every 15 mins
        if (!isset($_SESSION['last_regen'])) {
            $_SESSION['last_regen'] = time();
        } elseif (time() - $_SESSION['last_regen'] > 900) {
            session_regenerate_id(true);
            $_SESSION['last_regen'] = time();
        }
    }

    public static function validateInput($input, $type = 'string')
    {
        $input = trim((string)$input);
        if ($type === 'username') {
            return preg_match('/^[a-zA-Z0-9_\-\.@]+$/', $input) ? $input : null;
        }
        // Basic string sanitization
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    public static function csrfToken(): string
    {
        return $_SESSION['csrf_token'] ?? '';
    }

    public static function verifyCsrf(?string $token): bool
    {
        if (empty($token) || empty($_SESSION['csrf_token'])) return false;
        return hash_equals($_SESSION['csrf_token'], $token);
    }

    public static function e(?string $value): string
    {
        return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
    }

    public static function rateLimited(string $key, int $limit, int $window): bool
    {
        if (!isset($_SESSION['rl_' . $key])) $_SESSION['rl_' . $key] = [];
        $attempts = &$_SESSION['rl_' . $key];
        
        // Remove old attempts
        $attempts = array_filter($attempts, fn($t) => $t > time() - $window);
        
        if (count($attempts) >= $limit) return true;
        
        $attempts[] = time();
        return false;
    }

    public static function passwordHash($pwd): string {
        return password_hash($pwd, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function logout(): void {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
        header("Location: index.php");
        exit;
    }
}