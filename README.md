# Reconnaissance-Toolkit
This project aims to significantly reduce the manual effort required for tasks such as port scanning, vulnerability scanning  etc.

## Installation

#### Python

Recon Strike requires Python3+ and pip. Python 3.8 and pip can be installed using the following commands:

```
sudo apt install python3
sudo apt install python3-pip
```

#### Command Line Tools

The following commands may need to be installed, depending on your OS:

```
curl
enum4linux
gobuster
nikto
nmap
smbmap
whatweb
```

On Linux, you can ensure these are all installed using the following commands:

```
sudo apt install curl enum4linux gobuster nikto nmap smbclient smbmap whatweb
```

#### Installing Python Dependencies

Python dependencies can be installed using this command:

```
python3 -m pip install -r requirements.txt
```

## Usage

Use this command to launch Recon Strike menu

```
sudo python3 recon-strike.py
```
