<?php
require 'Medoo.php';
use Medoo\Medoo;

function getDB() {
    return new Medoo([
        'type' => 'sqlite',
        'database' => __DIR__ . '/ztd.sqlite'
    ]);
}
?>