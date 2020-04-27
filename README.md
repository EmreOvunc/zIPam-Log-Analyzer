# zIPam-Log-Analyzer
zIPam helps members to analyze network logs from an excel file. It runs 'whois' request to find organizations for blue teams.

## Roadmap
+ [x] .xlsx parsing
+ [x] GET requests to two whois web apps
+ [x] Subnet searching added
+ [x] xls and txt output 
+ [x] error output 
- [ ] API integration for security devices
- [ ] General log parsing


## Installation
```
git clone https://github.com/EmreOvunc/zIPam-Log-Analyzer.git
cd zIPam-Log-Analyzer
sudo pip3 install virtualenv
source myvenv/bin/activate
python3 zippam.py
```

## Example Output

![](https://emreovunc.com/projects/zippam_console.png)
