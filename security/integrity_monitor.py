import hashlib
import os

def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    try:

        with open(file_path, "rb") as file:

            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:

        return str(e)