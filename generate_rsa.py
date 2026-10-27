from Crypto.PublicKey import RSA

# Generate 2048-bit RSA key pair
key = RSA.generate(2048)

# Save private key (keep safe!)
with open("private.pem", "wb") as f:
    f.write(key.export_key('PEM'))

# Save public key (can share)
with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key('PEM'))

print("RSA keys generated: private.pem and public.pem")
