<?php
require 'Medoo.php';
use Medoo\Medoo;

session_start();

function getDB() {
    return new Medoo([
        'type' => 'sqlite',
        'database' => __DIR__ . '/ld.sqlite'
    ]);
}
?>