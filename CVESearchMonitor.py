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
from smtplib import SMTP
from email.message import EmailMessage
from datetime import date, timedelta
from packaging import version
from pprint import pprint, pformat

# Get directory of the running script
scriptDirectory = os.path.dirname(os.path.realpath(__file__))
# Process any provided argument
parser = argparse.ArgumentParser()
parser.add_argument("-a", "--assets", help="Specify the assets file to use (Default: './assets.cfg')", default = scriptDirectory + '/assets.cfg')
parser.add_argument("-c", "--config", help="Specify the configuration file to use (Default: './CVESearchMonitor.cfg')", default = scriptDirectory + '/CVESearchMonitor.cfg')
parser.add_argument("-l", "--local", help="Do not send report by email, but rather print in on stdout.", action='store_true')
parser.add_argument("-1", "--oneEmailPerCVE", help="Send one email for each new or updated CVE found. Doesn't apply when the --local argument is used.", action='store_true')
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
  asset['query'] = config[s].get('query').lower()
  if not asset['query']:
    print('Ignoring asset ' + s + ' as it has no query field.')
    continue
  asset['version'] = config[s].get('version')
  assets.append(asset)

# Get date of last run and default to all CVE from current year when last run date wasn't found.
try:
  if args.startDate:
    startDate = args.startDate
  else: 
    f = open( lastRunFile )
    startDate = f.read().rstrip()
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
    r = requests.get( url + '/query', headers=headers )
    r.raise_for_status()
    rjson = r.json()
    cveList += rjson

  except Exception as e: 
    print('Error while retrieving CVE') 
    print(e)

# Parse all CVE returned
newVulnerabilities = []
for item in cveList:

  # For all assets to be monitored, check if there's a match with the currently selected CVE
  for asset in assets:

    # First check if the cveData match the asset's query field
    cveData =  str(item['vulnerable_configuration'] + item['vulnerable_configuration_cpe_2_2']) + item['summary']
    if asset['query'] in cveData.lower():

      # The CVE match for the moment, but it might change if the asset has a version field
      cveMatch = True
      if asset['version']:

        # The asset has a version field, so it must also match
        cveMatch = False
        assetVersion = version.parse(asset['version'])

        # Parse CPE
        for cpe in item['vulnerable_configuration'] + item['vulnerable_configuration_cpe_2_2']: 
          cpeArray = cpe.split(":")
          try:
            # Get version from CPE
            if cpe.startswith("cpe:2.3"):
              cpeVersion = version.parse(cpe.split(":")[5])
            else:
              cpeVersion = version.parse(cpe.split(":")[4])
            # Only compare versions for matching products
            if asset['query'] in cpe:
              # Compare versions
              if assetVersion <= cpeVersion:
                cveMatch = True
                break
          except IndexError:
            # If we get the IndexError exception, that means, no version was defined in the CPE,
            # and we assume it matches our version if the query match in the cpe
            if asset['query'] in cpe:
              cveMatch = True
              break

      # The CVE matched, add it to the list of new vulnerabilities identified
      if cveMatch == True:
          cve = {}
          cve['asset'] = asset['name']
          cve['id'] = item['id']
          cve['summary'] = item['summary']
          cve['cvss'] = item['cvss']
          cve['url'] = url + '/cve/' + item['id']
          newVulnerabilities.append(cve)

# Compose one global email body by default. This will be overwritten later if needed
body = str(len(cveList)) + ' new CVE found from last run (' + startDate + ').\n'
body += str(len(newVulnerabilities)) + ' vulnerabilities found possibly applying monitored assets.\n'
body += '\n' + pformat(newVulnerabilities)

# Reporting
if args.local:
  # Print default body on stdout if requested. Default is to report is by email
  print(body)
else:
  # Send report by email
  msgs = []
  if args.oneEmailPerCVE:
    # Send 1 email per new CVE. Default is to send 1 global email
    for cve in newVulnerabilities:
      # Compose email's body (Overwrite default global body)
      body = 'New or updated CVE ' + cve['id'] + ' (criticality = ' + str(cve['cvss']) + ') has been found applying to your asset "' + cve['asset'] + '".\n'
      body += '\n' + "Here's a summary of this CVE:\n"
      body += '\n' + cve['summary'] + '\n'
      body += '\n' + 'You may find more information here: ' + cve['url']

      # Compose email
      msg = EmailMessage()
      msg.set_content(body)
      msg['Subject'] = 'CVESearchMon report: ' + cve['id']
      msg['From']    = sender
      msg['To']      = recipient
      
      # Add email to email queue
      msgs.append(msg)
  else:
    # 1 global email report. Uses default global email body
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = 'CVESearchMon report'
    msg['From']    = sender
    msg['To']      = recipient

    # Add email to email queue
    msgs.append(msg)

  # Send email(s)
  with SMTP(smtpServer) as smtp:
    for msg in msgs:
      smtp.send_message(msg)

# Save date of last run if needed
if not args.startDate:
  if not os.path.dirname(lastRunFile):
    print( os.path.dirname(lastRunFile) )
    os.makedirs( os.path.dirname(lastRunFile) )
  with open( lastRunFile, 'w' ) as f:
    f.write( str(date.today()) )
