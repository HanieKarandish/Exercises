import hashlib


class PasswordHasher:
    def __init__(self, hashing_func, salt="S3Cr3t"):
        self.salt = salt
        self.hashing_func = hashing_func

    def encrypt(self, cleartext: str) -> str:
        mixed = cleartext + self.salt
        # cleartext= self.hashing_func(mixed)
        mixed_bytes = mixed.encode()
        cleartext_hashed = self.hashing_func(mixed_bytes).hexdigest()
        return cleartext_hashed

    def verify(self, cleartext: str, secret: str):
        return self.encrypt(cleartext) == secret


password_hasher1 = PasswordHasher(hashlib.sha256)

print(password_hasher1.encrypt("the cleartext"))

print(password_hasher1.verify("the cleartext", "tOhkO57DcvO00O"))


'''class User(PasswordHasher):
    def __init__(self, username, password, salt, hashing_func):
        super().__init__(hashing_func, salt)
        self.username = username
        self.password = self.encrypt(password)'''


class User:
    def __init__(self, username, password, password_hasher: PasswordHasher = None):
        self.username = username
        self.password_hasher = password_hasher if password_hasher else PasswordHasher(
            salt="test")
        self.password = self.password_hasher.encrypt(password)

    def authenticate(self, pass_word):

        if self.password_hasher.verify(pass_word, self.password):
            return self
        else:
            return None

    def __str__(self):
        return f"Username: {self.username}, Password: {self.password}"


user1 = User("Hanie", "Pegah87", password_hasher1)

print(user1)
print(user1.authenticate("6o0rolwhugka23p9o8n6"))
