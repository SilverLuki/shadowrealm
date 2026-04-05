FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (excludes keys/ via .dockerignore)
COPY . .

# Remove any pre-generated keys that may have been copied in
RUN rm -rf keys/ && rm -f static/pubkey.pem

# Entrypoint: generate fresh keys at runtime, then start the app
CMD ["sh", "-c", "\
  python3 -c \"\
import os; \
from cryptography.hazmat.primitives.asymmetric import rsa; \
from cryptography.hazmat.primitives import serialization; \
os.makedirs('keys', exist_ok=True); \
pk = rsa.generate_private_key(public_exponent=65537, key_size=2048); \
priv = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()); \
pub  = pk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo); \
open('keys/private.pem','wb').write(priv); \
open('keys/public.pem','wb').write(pub); \
open('static/pubkey.pem','wb').write(pub); \
print('RSA keys generated.'); \
\" && python3 app.py"]

EXPOSE 5000
