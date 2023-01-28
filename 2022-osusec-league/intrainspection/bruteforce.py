import re
import subprocess
import time

intra_res = subprocess.run(["unzip", "intrainspection.zip"], capture_output=True)

zipname = "Safe.zip"
res = ""

password_regex = re.compile(r"pw == (\w{4})")
inner_regex = re.compile(r"extracting: (\w{4}\.zip)")

zip_start = time.perf_counter()

while "docx" not in res:
    bruteforce_res = subprocess.run(["fcrackzip", "-c", "aA", "-p", "aaaa", "-u", zipname], capture_output=True, text=True)
    zip_password = password_regex.search(bruteforce_res.stdout).group(1)
    print(f"Password for {zipname}: {zip_password}")
    res = subprocess.run(["unzip", "-P", zip_password, zipname], capture_output=True, text=True).stdout
    zip_match = inner_regex.search(res)

    if zip_match is not None:
        zipname = zip_match.group(1)
    
total_time = round(time.perf_counter() - zip_start)
minutes, seconds = divmod(total_time, 60)

print(f"finished decrypting zips! took {minutes} minutes and {seconds} seconds")

