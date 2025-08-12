# ECS Takeover Toolkit

**ECS Takeover Toolkit** is a specialized Python tool designed to assist with the walkthrough and exploitation of the **CloudGoat ECS Takeover** lab environment. It automates the enumeration of Docker containers, execution of commands inside them, and extraction of AWS credentials exposed within vulnerable ECS setups.

While primarily tested and developed for CloudGoat's `ecs_takeover` lab, this toolkit can also be adapted and used for other Remote Code Execution (RCE) scenarios involving Docker containers and AWS environments.

## Features

- Enumerate running Docker containers on the target ECS instance  
- Execute commands inside containers to gather user and environment information  
- Extract AWS credentials and IAM roles exposed within containers  
- Handle multiple containers with duplicate filtering  
- Clean and informative output for easy analysis  

## Installation

Ensure you have Python 3.x installed on your system.

Install the required Python libraries using pip:

```bash
pip install -r requirements.txt
````

Alternatively, install the dependencies individually:
```bash
pip install requests beautifulsoup4 urllib3
```
Usage
Run the toolkit with the target URL as an argument:

```
python ecs_takeover_toolkit.py --url http://target-url.com
```
## Proxy
You can enable proxy settings in the code if you want to debug the requests.

Decomment the "proxies" variable at the beginning an enable proxy where you need it like:

Example:
````python
os = requests.get(url +"/?" + input_id(url) + "=" + param_os_url)
````
Change to:
````python
os = requests.get(url +"/?" + input_id(url) + "=" + param_os_url, proxies=proxies)
````

The tool will:
Enumerate running Docker containers on the target
Attempt to execute commands inside each container
Extract and display AWS credentials and IAM roles if found

Disclaimer
This tool is intended for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

Contributing
Contributions and improvements are welcome!
