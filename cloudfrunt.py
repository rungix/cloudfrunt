#!/usr/bin/env python

# MIT License
# Copyright (c) 2017 Matt Westfall (@disloops)

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import time
import json
import boto3
import socket
import argparse
import textwrap

try:
    # Python 3
    from urllib.request import urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    # Python 2
    from urllib2 import urlopen, HTTPError, URLError

from subprocess import call
from netaddr import IPNetwork
from botocore.exceptions import ClientError

__author__ = 'Matt Westfall'
__version__ = '1.0.4'
__email__ = 'disloops@gmail.com'

# hotfix for dnsrecon (v0.8.12) to avoid user input
def patch_dnsrecon():

    with open('./dnsrecon/dnsrecon.py', 'r') as f:
        dnsrecon_data = f.read()
    dnsrecon_data = dnsrecon_data.replace('continue_brt = str(sys.stdin.readline()[:-1])','continue_brt = "n"')
    with open('./dnsrecon/dnsrecon.py', 'w') as f:
        f.write(dnsrecon_data)
    return True

# parse the input file
def get_domains(input_file):

    with open(input_file, 'r') as f:
        domains = f.readlines()
    domains = [domain.strip() for domain in domains]
    return domains

# grab all the CloudFront IP ranges
def get_cf_ranges(cf_url):

    response = None
    ranges = []

    while response is None:
        try:
            response = urlopen(cf_url)
        except URLError as e:
            print(' [?] Got URLError trying to get CloudFront IP ranges. Retrying...')
        except:
            print(' [?] Got an unexpected error trying to get CloudFront IP ranges. Exiting...')
            raise

    cf_data = json.load(response)
    for item in cf_data['prefixes']:
        service = item.get('service')
        if service == 'CLOUDFRONT':
            ranges.append(item.get('ip_prefix'))

    return ranges

# find more domains and correct for CloudFront
def recon_target(domain,cf_ranges,no_dns):

    dns_records = []

    if no_dns is not True:
        print(' [+] Enumerating DNS entries for ' + domain)
        with open(os.devnull, 'w') as devnull:
            call(['python','./dnsrecon/dnsrecon.py','-d' + domain,'-tstd,brt','-f','--lifetime=1','-joutput.json'], stdout=devnull, stderr=devnull)
        try:
            dns_records = json.load(open('output.json'))
            os.remove('output.json')
        except:
            pass
    else:
        return [domain] if get_cf_domain(domain,cf_ranges) else []

    if len(dns_records) > 1000:
        print(' [?] Is ' + domain + ' a wildcard domain? Skipping...')
        return [domain] if get_cf_domain(domain,cf_ranges) else []

    url_list = []
    for record in dns_records:
        if record.get('name') and (record.get('name') not in url_list) and get_cf_domain(record.get('name'),cf_ranges):
            url_list.append(str(record.get('name')).lower())

    return url_list

# check if domain points to CloudFront
def get_cf_domain(domain,cf_ranges):

    if domain.endswith('cloudfront.net'):
        return False

    domain_ips = []

    try:
        domain_ips = socket.gethostbyname_ex(domain)[2]
    except:
        pass

    for ip in domain_ips:
        for ip_range in cf_ranges:
            ip_network = IPNetwork(ip_range)
            if ip in ip_network:
                print(' [+] Found CloudFront domain --> ' + str(domain))
                return True
    return False

# test domains for CloudFront misconfigurations
def find_cf_issues(domains):

    error_domains = []

    for domain in domains:
        try:
            response = urlopen('http://' + domain)
        except HTTPError as e:
            if e.code == 403 and 'Bad request' in e.fp.read():
                try:
                    response = urlopen('https://' + domain)
                except URLError as e:
                    if 'handshake' in str(e).lower() or e.code == 403 and 'Bad request' in e.fp.read():
                        error_domains.append(domain)
                except:
                    pass
        except:
            pass

    return error_domains

# add a domain to CloudFront
def add_domain(domain,client,origin,origin_id,distribution_id):

    if not distribution_id:
        distribution_id = create_distribution(client,origin,origin_id)

    response = None
    while response is None:
        try:
            response = client.get_distribution_config(Id=distribution_id)
        except ClientError as e:
            print(' [?] Got boto3 error - ' + e.response['Error']['Code'] + ': ' + e.response['Error']['Message'])
            print(' [?] Retrying...')

    aliases = response['DistributionConfig']['Aliases']

    # default maximum number of CNAMEs for one distribution
    if aliases['Quantity'] == 100:
        distribution_id = create_distribution(client,origin,origin_id)
        response = client.get_distribution_config(Id=distribution_id)
        aliases = response['DistributionConfig']['Aliases']

    if 'Items' in aliases:
        aliases['Items'].append(domain)
    else:
        aliases['Items'] = [domain]

    aliases['Quantity'] += 1
    response['DistributionConfig']['Aliases'] = aliases

    added_domain = None
    while added_domain is None:
        try:
            added_domain = client.update_distribution(Id=distribution_id,DistributionConfig=response['DistributionConfig'],IfMatch=response['ETag'])
            print(' [+] Added ' + str(domain) + ' to CloudFront distribution ' + str(distribution_id))
        except client.exceptions.CNAMEAlreadyExists as e:
            print(' [?] The domain ' + str(domain) + ' is already part of another distribution.')
            added_domain = False
        except ClientError as e:
            print(' [?] Got boto3 error - ' + e.response['Error']['Code'] + ': ' + e.response['Error']['Message'])
            print(' [?] Retrying...')

    return distribution_id

# create a new CloudFront distribution
def create_distribution(client,origin,origin_id):

    # default distribution configuration
    base_cf_config = {
        'Comment': '',
        'Aliases': {
            'Quantity': 0,
            'Items': []
        },
        'Origins': {
            'Quantity': 1,
            'Items': [
                {
                    'OriginPath': '',
                    'CustomOriginConfig': {
                        'OriginSslProtocols': {
                            'Items': [
                                'TLSv1',
                                'TLSv1.1',
                                'TLSv1.2'
                            ],
                            'Quantity': 3
                        },
                        'OriginProtocolPolicy': 'http-only',
                        'OriginReadTimeout': 30,
                        'HTTPPort': 80,
                        'HTTPSPort': 443,
                        'OriginKeepaliveTimeout': 5
                    },
                    'CustomHeaders': {
                        'Quantity': 0
                    },
                    'Id': origin_id,
                    'DomainName': origin
                }
            ]
        },
        'CacheBehaviors': {
            'Quantity': 0
        },
        'IsIPV6Enabled': True,
        'Logging': {
            'Bucket': '',
            'Prefix': '',
            'Enabled': False,
            'IncludeCookies': False
        },
        'WebACLId': '',
        'DefaultRootObject': '',
        'PriceClass': 'PriceClass_All',
        'Enabled': True,
        'DefaultCacheBehavior': {
            'TrustedSigners': {
                'Enabled': False,
                'Quantity': 0
            },
            'LambdaFunctionAssociations': {
                'Quantity': 0
            },
            'TargetOriginId': origin_id,
            'ViewerProtocolPolicy': 'allow-all',
            'ForwardedValues': {
                'Headers': {
                    'Quantity': 0
                },
                'Cookies': {
                    'Forward': 'none'
                },
                'QueryStringCacheKeys': {
                    'Quantity': 0
                },
                'QueryString': False
            },
            'MaxTTL': 31536000,
            'SmoothStreaming': False,
            'DefaultTTL': 86400,
            'AllowedMethods': {
                'Items': [
                    'HEAD',
                    'GET'
                ],
                'CachedMethods': {
                    'Items': [
                        'HEAD',
                        'GET'
                    ],
                    'Quantity': 2
                },
                'Quantity': 2
            },
            'MinTTL': 0,
            'Compress': False
        },
        'CallerReference': str(time.time()*10).replace('.', ''),
        'ViewerCertificate': {
            'CloudFrontDefaultCertificate': True,
            'MinimumProtocolVersion': 'TLSv1',
            'CertificateSource': 'cloudfront'
        },
        'CustomErrorResponses': {
            'Quantity': 0
        },
        'HttpVersion': 'http2',
        'Restrictions': {
            'GeoRestriction': {
                'RestrictionType': 'none',
                'Quantity': 0
            }
        },
    }

    response = None
    while response is None:
        try:
            response = client.create_distribution(DistributionConfig=base_cf_config)
            distribution_id = response['Distribution']['Id']
            print(' [+] Created new CloudFront distribution ' + str(distribution_id))
        except ClientError as e:
            print(' [?] Got boto3 error - ' + e.response['Error']['Code'] + ': ' + e.response['Error']['Message'])
            print(' [?] Retrying...')

    return distribution_id

def main():

    # 1. Setup manual information

    logo_msg = '\n CloudFrunt v' + __version__

    epilog_msg = ('example:\n' +
                 ' $ python cloudfrunt.py -l list.txt -s\n' +
                 logo_msg + '\n A tool for identifying misconfigured CloudFront domains.' +
                 '\n\n NOTE: There are a couple dependencies for this program to work correctly:\n' +
                 '\n 1) pip install -r requirements.txt\n' +
                 '\n 2) If you did not use \"git clone --recursive ...\" you will need to run the following:\n' +
                 '\n $ git clone https://github.com/darkoperator/dnsrecon.git')

    parser = argparse.ArgumentParser(add_help=False,formatter_class=argparse.RawTextHelpFormatter,epilog=epilog_msg)
    parser.add_argument('-h', '--help', dest='show_help', action='store_true', help='Show this message and exit\n\n')
    parser.add_argument('-l', '--target-file', help='File containing a list of domains (one per line)\n\n', type=str)
    parser.add_argument('-d', '--domains', help='Comma-separated list of domains to scan\n\n', type=str)
    parser.add_argument('-o', '--origin', help='Add vulnerable domains to new distributions with this origin\n\n', type=str)
    parser.add_argument('-i', '--origin-id', help='The origin ID to use with new distributions\n\n', type=str)
    parser.add_argument('-s', '--save', dest='save', action='store_true', help='Save the results to results.txt\n\n')
    parser.add_argument('-N', '--no-dns', dest='no_dns', action='store_true', help='Do not use dnsrecon to expand scope\n')
    parser.set_defaults(show_help='False')
    parser.set_defaults(save='False')
    parser.set_defaults(no_dns='False')
    args = parser.parse_args()

    if args.show_help is True:
        print('')
        print(parser.format_help())
        sys.exit(0)

    print(logo_msg)

    # 2. Check input and handle the target list

    target_list = []

    if not args.target_file and not args.domains:
        print('')
        parser.error('\n\n Either --target-file or --domains is required.\n Or use --help for more info.\n')

    boto_client = None
    distribution_id = ''

    if (args.origin and not args.origin_id) or (args.origin_id and not args.origin):
        print('')
        parser.error('\n\n Both --origin and --origin-id are required to create new distributions.\n')
    elif args.origin and args.origin_id:
        boto_client = boto3.client('cloudfront')

    if args.no_dns is not True:
        if not os.path.isfile('./dnsrecon/dnsrecon.py'):
            print('')
            parser.error('\n\n The file \'./dnsrecon/dnsrecon.py\' was not found.\n Use -N to skip dnsrecon or use --help for more info.\n')
        else:
            patch_dnsrecon()

    if args.target_file:
        target_list = get_domains(args.target_file)

    if args.domains:
        for domain in [domain.strip() for domain in args.domains.split(',')]:
            target_list.append(domain)

    # 3. Adjust the scope and report findings

    cf_ranges = get_cf_ranges('https://ip-ranges.amazonaws.com/ip-ranges.json')
    target_list = [target.lower() for target in list(set(target_list))]

    for target in target_list:
    
        print('')
        target_scope = find_cf_issues(recon_target(target,cf_ranges,args.no_dns))

        if target_scope:
            print(' [-] Potentially misconfigured CloudFront domains:')

            for domain in target_scope:
                print(' [#] --> ' + domain)
                if args.origin:
                    distribution_id = add_domain(domain,boto_client,args.origin,args.origin_id,distribution_id)

            if args.save is True:
                with open('results.txt', 'a') as f:
                    print(' [-] Writing output to results.txt...')
                    for domain in target_scope:
                        f.write(str(domain) + '\n')
        else:
            print(' [-] No issues found for ' + target)

    print('')

if __name__ == '__main__':
    sys.exit(main())
