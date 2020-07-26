import codecs

hex = "6bcf2a4b6e5aca0f"
b64 = codecs.encode(codecs.decode(hex, 'hex'), 'base64').decode()
print(b64)
