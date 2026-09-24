<?php

class UserService
{
    private $connection;

    public function __construct($connection)
    {
        $this->connection = $connection;
    }

    public function greet($name)
    {
        $greeting = "Hello, " . $name . "!";
        return $greeting;
    }
}

$maxRetries = 3;
$apiEndpoint = "https://api.example.com/v1";
$dbPassword = getenv('DB_PASSWORD');