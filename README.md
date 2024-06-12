# Reconnaissance-Toolkit
The Recon Strike reconnaissance toolkit is a comprehensive system designed for performing enumeration and vulnerability assessments on host devices. It integrates multiple scanning techniques to identify and analyze potential security weaknesses.

![image](https://github.com/lakshayyverma/Reconnaissance-Toolkit/assets/72252002/44e9b2f2-14d1-4d6e-be49-22f755b357b3)

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
