import hashlib

def hash_message(message):
    """Return the SHA-256 hash of the given message."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(message.encode('utf-8'))
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    # Example usage
    message = "This is a secret message."
    hash_value = hash_message(message)
    print(f"Message: {message}")
    print(f"SHA-256 Hash: {hash_value}")
