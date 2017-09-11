## Spaghetti - Web Application Security Scanner v0.1.1
![build](https://img.shields.io/badge/build-passing-green.svg) ![python](https://img.shields.io/badge/python-2.7-green.svg)  ![license](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)

![logo](https://raw.githubusercontent.com/m4ll0k/Spaghetti/master/screens/logo.png)

## Description
Spaghetti is a web application security scanner tool. It is designed to find various default and insecure files, configurations and misconfigurations. Spaghetti is built on python2.7 and can run on any platform which has a Python environment.

![main](https://raw.githubusercontent.com/m4ll0k/Spaghetti/master/screens/screen1.png)

## Installation
```
$ git clone https://github.com/m4ll0k/Spaghetti.git
$ cd Spaghetti 
$ pip install -r requirements.txt
$ python spaghetti.py --help
```

## Features
- Fingerprints
  - Server
  - Web Frameworks (CakePHP,CherryPy,Django,...)
  - Web Application Firewall (Waf) (Cloudflare,AWS,Barracuda,...)
  - Content Management System (CMS) (Drupal,Joomla,Wordpress,Magento)
  - Operating System (Linux,Unix,Windows,...)
  - Language (PHP,Ruby,Python,ASP,...)
 
 ```
 Example: python spaghetti.py --url target.com --scan 0 --random-agent --verbose
 ```
 ![fingerprints](https://raw.githubusercontent.com/m4ll0k/Spaghetti/master/screens/screen2.png)

- Discovery:
  
  - Apache
    - Apache (mod_userdir)
    - Apache (mod_status)
    - Apache multiviews
    - Apache xss
  
  - Broken Auth./Session Management
    - Admin Panel
    - Backdoors
    - Backup Directory
    - Backup File
    - Common Directory
    - Common File
    - Log File
  
  - Disclosure
    - Emails
    - IP
  
  - Injection
    - HTML
    - SQL 
    - LDAP 
    - XPath
    - XSS
    - RFI
    - PHP Code
    
  - Other
    - Allow Methods
    - HTML Object
    - Multiple Index
    - Robots Paths
    - Cookie Security
    
  - Vulns
    - ShellShock
    - Struts-Shock
