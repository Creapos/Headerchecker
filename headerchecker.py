__author__ = 'prosec'

#### Libary imports

import re
import sys
import argparse
import configparser
import requests

#### Var defining
setup = False
rand = False #TODO Implemneting UA randomization
url = ""
conf_file ="/etc/headerchecker.conf"
default_conf_content= ""

##############
####Functions#
##############
def create_http_conn(url):
    request = requests.head(url)
    statuscode = request.status_code
    if statuscode != 200:
        print('HTTP Connection Error %s' %(statuscode))
    else : return request

def header_matcher(key,header):

    #Char transforming
    key = str(key)
    key = key.lstrip()
    key = key.rstrip()
    key = key.lower()

    header = str(header)
    header = header.lstrip()
    header = header.rstrip()
    header = header.lower()

    #Check
    if key == header:
        return True

def check_section(section):
    res = False
    print('Severity %s: ' %(section))
    for key in config[section]:
        for header in headers:
            res = header_matcher(key,header)
            if res :
                res = True
                break
        if not res :
            print("\tMissing: " + key)

#### Argumentparser
parser = argparse.ArgumentParser(prog='headerchecker.py', description="""#### ProSec rockZ ####""")
parser.add_argument("--setup", dest="setup", action="store_true", help="Installs conf files")
parser.add_argument("-u", "--url", dest="url", nargs=1, help='Specifies target url')
parser.add_argument("-c", "--config", dest="conf_file", default=conf_file, nargs=1, help='Specifies alterantive header file, default is in /etc/headerchecker.conf')

options = parser.parse_args()

if not options.setup :
    if not options.url :
        print('Please specify URL, more details via -h parameter')
        print(parser.print_usage())
        exit(1)
    url = options.url[0]

if options.conf_file :
    conf_file = options.conf_file[0]

#### Configparser

config = configparser.ConfigParser()

##########
#### Main#
##########

#### SETUP
if options.setup :
    config['High'] = {}
    config['Medium'] = {'X-XSS-Protection': '1; mode=block',
                        'Strict-Transport-Security': 'Bool', }
    config['Low'] = {'X-Frame-Options': 'deny|sameorigin',
                      'Content-Type': 'Bool',
                      'Content-Security-Policy' : 'Bool',
                      'Public-Key-Pins': 'Bool',
                      'X-Robots-Tag' : 'Bool'}

    try :
        with open(conf_file, 'w+') as file:
                config.write(file, "UTF-8")
                print('Setup completed, you can config headers manual under %s' %(conf_file))
    except Exception as e:
        print("Following Error occurred when creating config file: \r\n %s" %(e))
        exit(1)

#    exit(0)

#### Read Config
try :
    with open(conf_file, 'r') as configfile:
        config.readfp(configfile, 'UTF-8')
except Exception as e:
    print("Could not open config file")
    print(e)

#### Parsing target
request = create_http_conn(url)
headers_unfiltered = request.headers
headers = []

for header in headers_unfiltered :
    headers.append(header)

#### Header check
print('Following vulns has been found: \r\n')
check_section("High")
check_section("Medium")
check_section("Low")

