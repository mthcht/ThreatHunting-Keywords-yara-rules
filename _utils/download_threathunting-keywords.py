import os
import hashlib
import requests
from urllib.parse import urlparse

def calculate_hash(file_path):
    with open(file_path, 'rb') as file:
        bytes = file.read() 
        readable_hash = hashlib.sha256(bytes).hexdigest()
    return readable_hash

def download_file(url):
    try:
        parsed_url = urlparse(url)
        if not (parsed_url.scheme and parsed_url.netloc and parsed_url.path):
            print("Invalid URL")
            return

        dir_path = os.path.dirname(os.path.realpath(__file__))

        file_name = os.path.basename(parsed_url.path)
        if not file_name:
            print("URL does not contain a file name")
            return

        full_file_path = os.path.join(dir_path, file_name)

        r = requests.get(url, allow_redirects=True, verify=True)
        if r.status_code != requests.codes.ok:
            print(f"Failed to download file, status code: {r.status_code}")
            return

        if os.path.exists(full_file_path):
            existing_file_hash = calculate_hash(full_file_path)
            downloaded_file_hash = hashlib.sha256(r.content).hexdigest()
            if existing_file_hash == downloaded_file_hash:
                print(f"File already exists and is identical: {full_file_path}")
                return
            else:
                print(f"File exists but is different, overwriting: {full_file_path}")
                # Write content in file.
                with open(full_file_path, 'wb') as file:
                    file.write(r.content)
                    print(f"File downloaded successfully: {full_file_path}")
                    return "success"
    except Exception as e:
        print(f"An error occurred: {str(e)}")


downloaded = download_file("https://github.com/mthcht/ThreatHunting-Keywords/raw/main/threathunting-keywords.csv")
if downloaded:
    print(f"success")
else:
    print(f"ko")