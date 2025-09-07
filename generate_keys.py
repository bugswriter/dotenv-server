# generate_key.py
from cryptography.fernet import Fernet

# This function creates a URL-safe, base64-encoded 32-byte key
# and then converts it to a string for easy storage.
key = Fernet.generate_key().decode()

print("Your new Fernet key is:")
print(f"ENCRYPTION_KEY='{key}'")
