import base64

print("only tested for es256 for now")
print("input the pubkey string:")
pubkey_string_b64 = input()

# output
print(pubkey_string_b64)

pubkey_bytes = base64.b64decode(pubkey_string_b64)
print(pubkey_bytes)

pubkey_hex = pubkey_bytes.hex()
print(pubkey_hex)

# remove prefix
pubkey_hex_coordinates = pubkey_hex[54:]
print(pubkey_hex_coordinates)

coordinate_x = pubkey_hex_coordinates[:len(pubkey_hex_coordinates)//2]
coordinate_y = pubkey_hex_coordinates[len(pubkey_hex_coordinates)//2:]
print(coordinate_x)
print(coordinate_y)

coordinate_x_string_b64 = base64.urlsafe_b64encode(
    bytes.fromhex(coordinate_x)).decode("utf-8")
coordinate_y_string_b64 = base64.urlsafe_b64encode(
    bytes.fromhex(coordinate_y)).decode("utf-8")
print(coordinate_x_string_b64[:-1])
print(coordinate_y_string_b64[:-1])
