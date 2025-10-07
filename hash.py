import hashlib
senha = "IPutMyFingsIntoMyEyes"
hash_senha = hashlib.sha256(senha.encode()).hexdigest()
print(hash_senha)
