import zlib
import os


def compress_file(file_name):
    with open(file_name, "rb") as file:
        data = file.read()
    compressed_data = zlib.compress(data)
    compressed_file_name = file_name + ".zlib"

    with open(compressed_file_name, "wb") as compressed_file:
        compressed_file.write(compressed_data)
    os.remove(file_name)


def decompress_file(compressed_file_name):
    with open(compressed_file_name, "rb") as compressed_file:
        compressed_data = compressed_file.read()
    decompressed_data = zlib.decompress(compressed_data)
    original_file_name = compressed_file_name.replace(".zlib", "")

    with open(original_file_name, "wb") as file:
        file.write(decompressed_data)
    os.remove(compressed_file_name)
