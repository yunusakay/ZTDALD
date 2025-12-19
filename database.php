<?php
class Database {
    private static $instance = null;
    private $pdo;
    
    private function __construct() {
        $host = 'localhost';
        $db   = 'ZTALDB';
        $user = 'root';
        $pass = '';
        
        try {
            $this->pdo = new PDO("mysql:host=$host;dbname=$db;charset=utf8", $user, $pass);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die("Veritabanı Hatası: " . $e->getMessage());
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function getConnection() {
        return $this->pdo;
    }
    
    public function getConfig() {
        return require __DIR__ . '/security_config.php';
    }
    
    public function select($table, $where = [], $columns = '*') {
        $pdo = $this->getConnection();
        
        $sql = "SELECT $columns FROM $table";
        $params = [];
        
        if (!empty($where)) {
            $conditions = [];
            foreach ($where as $key => $value) {
                $conditions[] = "$key = ?";
                $params[] = $value;
            }
            $sql .= " WHERE " . implode(' AND ', $conditions);
        }
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }
    
    public function insert($table, $data) {
        $pdo = $this->getConnection();
        
        $columns = implode(', ', array_keys($data));
        $placeholders = str_repeat('?,', count($data) - 1) . '?';
        
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array_values($data));
        
        return $pdo->lastInsertId();
    }
    
    public function delete($table, $where) {
        $pdo = $this->getConnection();
        
        $conditions = [];
        $params = [];
        
        foreach ($where as $key => $value) {
            $conditions[] = "$key = ?";
            $params[] = $value;
        }
        
        $sql = "DELETE FROM $table WHERE " . implode(' AND ', $conditions);
        
        $stmt = $pdo->prepare($sql);
        return $stmt->execute($params);
    }
    
    public function update($table, $data, $where) {
        $pdo = $this->getConnection();
        
        $set = [];
        $params = [];
        
        foreach ($data as $key => $value) {
            $set[] = "$key = ?";
            $params[] = $value;
        }
        
        foreach ($where as $key => $value) {
            $params[] = $value;
        }
        
        $sql = "UPDATE $table SET " . implode(', ', $set) . " WHERE " . implode(' AND ', array_map(fn($k) => "$k = ?", array_keys($where)));
        
        $stmt = $pdo->prepare($sql);
        return $stmt->execute($params);
    }
}
