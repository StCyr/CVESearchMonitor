#!/usr/bin/python3

# This script is intended to be run once a day in the morning.
# It uses CIRCL.LU's CVE Search service to try and find new CVE's 
# issued the day before that could affect the assets defined
# in the 'assets' variable.
# The match is made via a simple case insensitive substring search
# against the CVE's 'summary', 'vulnerable_configuration', and
# 'vulnerable_configuration_cpe_2_2' fields. 

import os
import argparse
import configparser
import requests
import smtplib
from email.message import EmailMessage
from datetime import date, timedelta
from pprint import pprint, pformat

# Get directory of the running script
scriptDirectory = os.path.dirname(os.path.realpath(__file__))
# Process any provided argument
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--assets", help="Specify the assets file to use (Default: './assets.cfg')", default = scriptDirectory + '/assets.cfg')
parser.add_argument("-c", "--config", help="Specify the configuration file to use (Default: './CVESearchMonitor.cfg')", default = scriptDirectory + '/CVESearchMonitor.cfg')
parser.add_argument("-l", "--local", help="Do not send report by email, but rather print in on stdout", action='store_true')
parser.add_argument("-s", "--startDate", help="Specify the date (format 'YYYY-MM-DD') from which CVE must be retrieved. When this argument is passed, the last run \
                                          date from 'lastRunFile' (see configuration file) is not used and not updated. When no last run date is found, and this argument isn't provided, \
                                          CVESearchMonitor will retrieved all CVE's modified during the last 30 days")
args = parser.parse_args()

# Read configuration
config = configparser.ConfigParser()
config.read(args.config)
 
# Setup global variables
url         = config['GLOBAL']['url']
lastRunFile = config['GLOBAL']['lastRunFile']
smtpServer  = config['GLOBAL']['smtpServer']
sender      = config['GLOBAL']['sender']
recipient   = config['GLOBAL']['recipient']

# Read assets
config = configparser.ConfigParser()
config.read(args.assets)
assets = []
for s in config.sections():
  asset = {}
  asset['name'] = s
  asset['description'] = config[s].get('description', 'Not defined')
  asset['query'] = config[s].get('query')
  if not asset['query']:
    print('Ignoring asset ' + s + ' as it has no query field.')
    continue
  assets.append(asset)

# Get date of last run and default to all CVE from current year when last run date wasn't found.
try:
  if args.startDate:
    startDate = args.startDate
  else: 
    f = open( lastRunFile )
    startDate = f.read()
except:
  startDate = str(date.today() - timedelta(30))

# Get all CVE's from sartDate by batch of 50 CVE's
cveList = []
headers = { 'Accept' : 'text/json' , 'time_modifier': 'from' , 'time_type' : 'last-modified' , 'time_start' : startDate , 'limit' : '50' }
rjson   = [None]*50
while len(rjson)==50:

  # Skip already retrieved CVE's
  headers['skip'] = str(len(cveList))

  # Send request to CVE-Search instance, decode result, and append it to the list of CVE's already retrieved
  try: 
    r = requests.get( url, headers=headers )
    r.raise_for_status()
    rjson = r.json()
    cveList += rjson

  except Exception as e: 
    print('Error while retrieving CVE') 
    print(e)

# Parse all CVE returned
newVulnerabilities = []
for item in cveList:

  # For all assets to be monitored, check if there's a match with any of 
  # the CVE's 'vulnerabl_²configuration', 'vulnerable_configuration_cpe_2_2' or 'summary' fields
  for asset in assets:
    cveData =  str(item['vulnerable_configuration'] + item['vulnerable_configuration_cpe_2_2']) + item['summary']
    if asset['query'] in cveData.lower():
      cve = {}
      cve['asset'] = asset['name']
      cve['id'] = item['id']
      cve['summary'] = item['summary']
      cve['cvss'] = item['cvss']
      cve['vulnerable_configuration'] = item['vulnerable_configuration']
      cve['vulnerable_configuration_cpe_2_2'] = item['vulnerable_configuration_cpe_2_2']
      newVulnerabilities.append(cve)

# Compose body of report email
body = str(len(cveList)) + ' new CVE found from last run (' + startDate + ').\n'
body += str(len(newVulnerabilities)) + ' vulnerabilities found possibly applying monitored assets.\n'
body += '\n'
body += pformat(newVulnerabilities)

# Reporting
if args.local:
  # Print on stdout if requested
  print(body)
else:
  # Default reporting is by email
  msg = EmailMessage()
  msg.set_content(body)
  msg['Subject'] = 'CVESearchMon report'
  msg['From']    = sender
  msg['To']      = recipient

  # Send email
  s = smtplib.SMTP(smtpServer)
  s.send_message(msg)
  s.quit()

# Save date of last run if needed
if not args.startDate:
  if not os.path.dirname(lastRunFile):
    print( os.path.dirname(lastRunFile) )
    os.makedirs( os.path.dirname(lastRunFile) )
  with open( lastRunFile, 'w' ) as f:
    f.write( str(date.today()) )
