# CVESearchMonitor

A simple tool designed to monitor a CVE-Search (https://github.com/cve-search/cve-search) instance
at regular interval (eg. via a cron job) to look for new CVE's that could affect your assets.

# Usage

CVESearchMonitor.py --help

usage: CVESearchMonitor.py [-h] [-a ASSETS] [-c CONFIG] [-l] [-s STARTDATE]

optional arguments:

  -h, --help            show this help message and exit  
  -a ASSETS, --assets ASSETS  
                        Specify the assets file to use (Default:
                        './assets.cfg')  
  -c CONFIG, --config CONFIG  
                        Specify the configuration file to use (Default:
                        './CVESearchMonitor.cfg')  
  -l, --local           Do not send report by email, but rather print in on
                        stdout  
  -s STARTDATE, --startDate STARTDATE  
                        Specify the date (format 'YYYY-MM-DD') from which CVE
                        must be retrieved. When this argument is passed, the
                        last run date from 'lastRunFile' (see configuration
                        file) is not used and not updated. When no last run
                        date is found, and this argument isn't provided,
                        CVESearchMonitor will retrieved all CVE's modified
                        during the last 30 days

# Example

./CVESearchMonitor.py -a my_assets.cfg -l -s 2018-09-17

126 new CVE found from last run (2018-09-17).  
2 vulnerabilities found possibly applying to monitored assets.

[{'asset': 'Flash player',  
  'cvss': 5.0,  
  'id': 'CVE-2018-5008',  
  'summary': 'Adobe Flash Player 30.0.0.113 and earlier versions have an '
             'Out-of-bounds read vulnerability. Successful exploitation could '
             'lead to information disclosure.'},  
 {'asset': 'Flash player',  
  'cvss': 6.8,  
  'id': 'CVE-2018-5007',  
  'summary': 'Adobe Flash Player 30.0.0.113 and earlier versions have a Type '
             'Confusion vulnerability. Successful exploitation could lead to '
             'arbitrary code execution in the context of the current user.'}]

# Requirements

* A working CVE-Search instance
* A working SMTP server
* Python 3
* Python's packaging module (package python3-packaging on Ubuntu)
