import os


class UserService:
    def __init__(self, connection):
        self.connection = connection

    def greet(self, name):
        greeting = "Hello, " + name + "!"
        return greeting


MAX_RETRIES = 3
API_ENDPOINT = "https://api.example.com/v1"
DB_PASSWORD = os.getenv("DB_PASSWORD")