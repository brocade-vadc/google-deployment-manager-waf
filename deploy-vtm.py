#!/usr/bin/python
# Copyright (C) 2016, Brocade Communications Systems. All rights reserved.

"""Wrapper for Brocade vTM/vWAF scripts for Google Deployment Manager"""

import argparse
from argparse import RawTextHelpFormatter
import re
import sys
import os
import os.path
import subprocess

###############################################################################
# Arguments
###############################################################################

# List of currently available SKUs
available_sku = {
   'safpx-csub-1000': 'Web Application Firewall (WAF)',
   'stm-csub-1000-h-saf': 'Standard vTM (1G) + WAF',
   'stm-csub-1000-l-saf': 'Standard vTM (10M) + WAF',
   'stm-csub-1000-m-saf': 'Standard vTM (200M) + WAF',
   'stm-csub-2000-l-saf': 'Enterprise vTM (1G) + WAF',
   'stm-dev-64': 'Developer vTM (1M)*',
}
sku_list = available_sku.keys()
sku_list.sort()
sku_string = ''
for sku in sku_list:
   padding = ' ' * (20 - len(sku))
   sku_string = ''.join([sku_string, sku, padding, '- ', available_sku[sku], '\n'])

parser = argparse.ArgumentParser(
            formatter_class=RawTextHelpFormatter,
            description="""
Create a Brocade Virtual Web Application Firewall deployment on Google Compute Engine.

Requirements:
 - This script is intended for use with Python 2.7
 - The 'gcloud' tool must be available via your PATH environment variable
 - GCE project metadata must contain a 'vtm-pass' item containing the password
   of the Brocade vTM 'admin' user
 - GCE project must have a service account
 - Startup scripts for the backend instances must add the instance to the
   Brocade vTM pool using the REST API (available at port 9070 by default)
 - Shutdown scripts must equivalently remove the instance from the pool

Available SKUs:
%(sku-list)s
* Note that Developer vTM also includes WAF

""" % {'sku-list': sku_string})
parser.add_argument( '--prefix',
                     default='brcd-dm-',
                     help='a prefix on the names of all resources created by this script'
                   )
parser.add_argument( '--subnet',
                     default='10.0.0.1/16',
                     help='the IP address range the new network will use'
                   )
parser.add_argument( '--existing-network',
                     help='an existing network to use instead of creating a new one',
                   )
#parser.add_argument( '--add-external-ips',
#                     help='add ephemeral IP addresses to instances created in this deployment',
#                     action='store_true',
#                   )
parser.add_argument( '--add-backends',
                     help='''create an autoscaled group of backend instances, with firewall rules for
ports 80 and 443 to allow traffic from the Brocade vWAF group''',
                     action='store_true'
                   )
parser.add_argument( '--backend-startup-script',
                     help='path to a file containing a script the backend instances should run on startup',
                   )
parser.add_argument( '--backend-shutdown-script',
                     help='path to a file containing a script the backend instances should run on shutdown',
                   )
parser.add_argument( '--sku',
                     help='the Brocade vTM SKU to deploy. Default: stm-csub-2000-l-saf',
                     choices=sku_list,
                     default='stm-csub-2000-l-saf',
                     metavar='',
                   )
parser.add_argument( '--version',
                     type=int,
                     default=111,
                     help='the Brocade vTM version to use, with no dot. e.g. "11.1"=>"111". Default: 111',
                   )
parser.add_argument( '--machine-type',
                     help='the Google Compute Engine instance type. Default: n1-standard-2',
                     default='n1-standard-2',
                   )
parser.add_argument( '--nodelete',
                     help='do not delete the deployment manager script files after running the gcloud command',
                     action='store_true'
                   )
parser.add_argument( '--nodeploy',
                     help='create the script files without creating a deployment',
                     action='store_true'
                   )
required_args = parser.add_argument_group('required arguments')
required_args.add_argument( '--region',
                     required = True,
                     help='the region all resources will be created in'
                   )
required_args.add_argument( '--zone',
                     required = True,
                     help='the zone to use for zone-specific resources',
                   )

args = parser.parse_args()

# Optional
PREFIX = args.prefix
SUBNET = args.subnet
CURRENT_NETWORK = args.existing_network
ADD_WEBSERVERS = args.add_backends
BACKEND_STARTUP_PATH = args.backend_startup_script
BACKEND_SHUTDOWN_PATH = args.backend_shutdown_script
KEEP_FILES = args.nodelete
NO_DEPLOY = args.nodeploy
SKU = args.sku
MACHINE_TYPE = args.machine_type
#ADD_EXTERNAL = args.add_external_ips
ADD_EXTERNAL = True

# Required
REGION = args.region
ZONE = args.zone
VERSION = str(args.version)

# Validate arguments #

zones = {}
try:
   out = subprocess.Popen(['gcloud', 'compute', 'zones', 'list'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   output, error = out.communicate()

   if out.returncode == 0:
      for line in output.splitlines():
         # e.g. "europe-west1-b  europe-west1  UP"
         match = re.match('\w+-\w+-(\w)\s+(\S+)\s+(\w+)', line)
         if match:
            zone, region, state = match.groups()
            if region not in zones:
               zones[region] = {}
            if zone not in zones[region]:
               if state.lower() == 'up':
                  zones[region][zone] = 1
               else:
                  zones[region][zone] = 0
   else:
      sys.stderr.write(error)
except:
   sys.stderr.write('ERROR: Unable to determine available zones via gcloud\n')
   sys.exit(1)

if not len(zones):
   sys.stderr.write('ERROR: Could not parse list of zones returned from gcloud\n')

if REGION not in zones:
   sys.stderr.write("ERROR: Region does not appear to be valid: %s\n" % REGION)
   sys.exit(1)

if ZONE not in zones[REGION]:
   sys.stderr.write("ERROR: Zone '%s' not valid for region '%s'\n" % (ZONE, REGION))
   sys.exit(1)

if zones[REGION][ZONE] != 1:
   sys.stderr.write("ERROR: %s-%s is currently unavailable (check 'gcloud compute zones list')\n" % (REGION, ZONE))
   sys.exit(1)

ZONE = ''.join([REGION, '-', ZONE])

if PREFIX[-1] != '-':
   PREFIX = ''.join([PREFIX, '-'])
if not re.match('^([a-z]([-a-z0-9]{0,46})?)$', PREFIX):
   sys.stderr.write("ERROR: Object prefix must consist of lowercase "
                    "alphanumeric characters and hyphens, start with "
                    "a letter, and not exceed 46 characters\n")
   sys.exit(1)

if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}$",SUBNET):
   sys.stderr.write("ERROR: Subnet must be provided in CIDR prefix form\n")
   sys.exit(1)

if CURRENT_NETWORK is not None:
   network_found = 0
   try:
      out = subprocess.Popen(['gcloud', 'compute', 'networks', 'list'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      output, error = out.communicate()

      if out.returncode == 0:
         for line in output.splitlines():
            elem_list = line.split()
            if elem_list[0] == CURRENT_NETWORK:
               network_found = 1
               break
      else:
         sys.stderr.write(error)
   except:
      sys.stderr.write('ERROR: Unable to determine available zones via gcloud\n')
      sys.exit(1)
   if network_found == 0:
      sys.stderr.write( 'ERROR: Specified network does not exist\n' )
      sys.exit(1)

for filepath in [ BACKEND_STARTUP_PATH, BACKEND_SHUTDOWN_PATH ]:
   if filepath is not None:
      if not os.path.isfile(filepath):
         sys.stderr.write(''.join(['ERROR: Cannot locate "', filepath, '"\n']))
         sys.exit(1)
      else:
         file_info = os.stat(filepath)
         if file_info.st_size > 32768:
            sys.stderr.write(''.join(['ERROR: Script "', filepath, '" is larger than 32768 bytes\n']))
            sys.exit(1)

valid_machine_type = False
try:
   out = subprocess.Popen(['gcloud', 'compute', 'machine-types', 'list', '--zones', ZONE],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   output, error = out.communicate()

   if out.returncode == 0:
      for line in output.splitlines():
         match = re.match('^(\S+)', line)
         if match:
            type = match.group(1)
            if type == MACHINE_TYPE:
               valid_machine_type = True
               break
   else:
      sys.stderr.write(error)
except:
   sys.stderr.write('ERROR: Unable to determine available machine types via gcloud\n')
   sys.exit(1)
if not valid_machine_type:
   sys.stderr.write(''.join(['ERROR: ', MACHINE_TYPE, ' does not appear to be a valid machine type for ', ZONE, '\n']))
   sys.exit(1)

###############################################################################
# Constants / Variables
###############################################################################

WAF_INSTANCE_TEMPLATE = ''.join([PREFIX, 'it-waf'])
WAF_TARGET_POOL = ''.join([PREFIX, 'tp-waf'])
WAF_INSTANCE_GROUP_MANAGER = ''.join([PREFIX, 'igm-waf'])
WAF_HEALTH_CHECK = ''.join([PREFIX, 'health-check'])

BACKEND_INSTANCE_TEMPLATE = ''.join([PREFIX, 'it-backend'])
BACKEND_INSTANCE_GROUP_MANAGER = ''.join([PREFIX, 'igm-backend'])

COMPUTE_BASE_URL = 'https://www.googleapis.com/compute/v1/'
VTM_IMAGE = ''.join([ 'vtm-', VERSION, '-', SKU ])
UBUNTU_IMAGE = 'family/ubuntu-1604-lts'
BRCD_PROJECT = 'brocade-public-1063'
UBUNTU_PROJECT = 'ubuntu-os-cloud'

WAF_TAG = 'vtm-waf'
BACKEND_TAG = 'vtm-backend'

WAF_MASTER_PORT = 11000
WAF_SLAVE_PORT = 11002
WAF_REST_PORT = 11003
WAF_UPDATER_PORT = 11007
WAF_DECIDER_PORT = 11008

VTM_REST_PORT = 9070
VTM_CONTROL_PORT = 9080
VTM_ADMIN_PORT = 9090
VTM_HEALTH_PORT = 9091

SCRIPT_FILES = [
   'brcd-config.yaml',
   'brcd-master.py',
   'brcd-instance-template.py',
   'brcd-instance-group-manager.py',
   'brcd-autoscaler.py',
   'brcd-firewall.py',
   'brcd-target-pool.py',
   'brcd-health-check.py',
   'brcd-forwarding-rule.py',
]

if CURRENT_NETWORK is not None:
   NETWORK = CURRENT_NETWORK
   NETWORK_REF = CURRENT_NETWORK
else:
   NETWORK = ''.join([PREFIX, 'network'])
   NETWORK_REF = ''.join(['$(ref.', NETWORK, '.selfLink)'])
   SCRIPT_FILES.append('brcd-network.py')

SERVICE_ACCOUNT = ''
try:
   out = subprocess.Popen(['gcloud', 'compute', 'project-info', 'describe'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   output, error = out.communicate()

   if out.returncode == 0:
      for line in output.splitlines():
         match = re.match('defaultServiceAccount:\s+(.+)$', line)
         if match:
            service_acct = match.group(1)
            SERVICE_ACCOUNT = service_acct
   else:
      sys.stderr.write(error)
except:
   sys.stderr.write('ERROR: Unable to retrieve project info\n')
   sys.exit(1)

VWAF_STARTUP_SCRIPT = r'''
#!/bin/sh
# Copyright (C) 2016, Brocade Communications Systems. All rights reserved.

cat > brcd_startup.py <<BRCDSTARTUP
#! /usr/bin/python

import subprocess
import sys
import os
import json

try:
   instance = subprocess.check_output("/usr/lib/google-cloud-sdk/bin/gcloud compute project-info describe --format='json'", shell=True).strip()
   metadata = json.loads(instance)
   metadata = metadata['commonInstanceMetadata']['items']
except:
   sys.stderr.write( "Unable to get metadata\n" )
   sys.exit(1)

for i in metadata:
   if i['key'] == "vtm-pass":
      passwd = i['value']
      break

try:
   with open('/root/brcd-dm_replay.txt', 'w') as f:
      f.write(r"""accept_license=accept
license_key=
password=%(passwd)s
rest_enabled=y
rest_port=9070
ssh_intrusion=y
timezone=UTC
""" % { 'passwd': passwd }
      )
      f.close()
except:
   sys.stderr.write('Failed to create replay.txt\n')
   sys.exit(1)

try:
   with open('/root/brcd-dm_auto-cluster', 'w') as f:
      f.write(
r"""#!/bin/sh
# Copyright (C) 2016, Brocade Communications Systems. All rights reserved.

ZEUSHOME=/opt/zeus
export ZEUSHOME=/opt/zeus
exec /opt/zeus/perl/miniperl -x \$0 \${1+"\\\$@"}

#!perl -w
#line 9

BEGIN { unshift @INC, "\$ENV{ZEUSHOME}/admin/lib/perl", "\$ENV{ZEUSHOME}/zxtm/lib/perl",
     "\$ENV{ZEUSHOME}/zxtmadmin/lib/perl"
      }

# Do not delete Flavour or ApplianceUtils - they are required to avoid a
# circular inclusion in our Exporter
use Zeus::ZXTM::Flavour;
use Zeus::ZXTM::ApplianceUtils qw( hasApplianceFeature );

use Zeus::ZXTM::GCEUtils qw( GCEMetadata gcloud_compute getGCEShortHostname parse_gcloud );
use Zeus::ZXTM::Configure;

use warnings;
use strict;

# Instance details
my \$hostname = getGCEShortHostname();
my \$zone = GCEMetadata( 'zone' );
\$zone =~ s|^.+?zones/([-a-z0-9]+)|\$1|;

my \$region = ( \$zone =~ /^(.+)-\d+\$/ );

my %zones;
my \$zones_raw = gcloud_compute( 'zones', 'list' );
foreach my \$line ( split( "\n", \$zones_raw ) ) {
   if( \$line =~ /^(\w+-\w+-\w+)\s+(\w+-\w+)\s+/ ) {
      if( !exists( \$zones{\$2} ) ) {
         \$zones{\$2} = \$1;
      } else {
         \$zones{\$2} = \$zones{\$2} . ",\$1";
      }
   }
}

# List all instances in the project which have the specified tag.
# Returns parse_gcloud hashref.
sub list_instances_by_filter(\$;\$)
{
   my( \$filter, \$all_regions ) = @_;
   if( !\$filter ) {
      return {};
   }

   my \$zone_list = '';
   if( !\$all_regions ) {
      \$zone_list = \$zones{\$region};
   }

   my \$raw = gcloud_compute( 'instances', 'list', "--filter=tags.items:\$filter" );
   if( !defined( \$raw ) ) {
      print STDERR "ERROR: 'gcloud compute instances list' failed to run\n";
      exit 1;
   }

   my \$parsed = parse_gcloud( \$raw, 'name' );
   return \$parsed;
}

sub tag(\$\$)
{
   my( \$action, \$tag ) = @_;
   if( !\$action || !\$tag || ( \$action ne 'add' && \$action ne 'remove' ) ) {
      return 0;
   }

   my( \$exit, \$out ) = gcloud_compute( 'instances', "\$action-tags", \$hostname, "--tags=\$tag", "--zone=\$zone" );
   if( !\$exit ) {
      print STDERR "ERROR: Failed to \$action tag '\$tag' to \$hostname\n";
   }
   return \$exit;
}

my \$username = GCEMetadata( 'attributes/vtm-user', undef, 1 );
my \$password = GCEMetadata( 'attributes/vtm-pass', undef, 1 );

if( !defined( \$username ) ) {
   \$username = 'admin';
}

if( !defined( \$password ) ) {
   print STDERR "ERROR: Failed to get Brocade vTM admin password from metadata\n";
   exit 1;
}

my \$cluster = {};
my \$cluster_size = 0;
while() {
   \$cluster = list_instances_by_filter( 'vtm-cluster' );
   \$cluster_size = scalar( keys( %{\$cluster} ) );

   if( !\$cluster_size ) {
      # We do not have a cluster yet - begin negotiating a cluster master
      tag( 'add', 'vtm-joining' );
      sleep( 10 );

      my \$joining = list_instances_by_filter( 'vtm-joining' );
      my @potentials = sort( keys( %{\$joining} ) );

      if( scalar( @potentials ) && \$potentials[0] ne \$hostname ) {
         tag( 'remove', 'vtm-joining' );
         sleep( 5 );
         last;
      } else {
         # Check again
         \$cluster = list_instances_by_filter( 'vtm-cluster' );
         \$cluster_size = scalar( keys( %{\$cluster} ) );
         if( \$cluster_size ) {
            # Someone beat us to it, they win
            tag( 'remove', 'vtm-joining' );
            last;
         }
         # We are the cluster. Yay for us.
         tag( 'add', 'vtm-cluster' );
         \$cluster = list_instances_by_filter( 'vtm-cluster' );
         if( scalar( keys( %{\$cluster} ) ) > 1 ) {
            # We clashed with another vTM, remove the tag and do a random backoff
            tag( 'remove', 'vtm-cluster' );
            sleep( int( rand( 20 ) ) );
            next;
         }
         tag( 'remove', 'vtm-joining' );
         exit 0;
      }
   } else {
      # A cluster exists! We should join it, break out of the negotiation loop.
      last;
   }
}

\$cluster = list_instances_by_filter( 'vtm-cluster' );

# Attempt to join the cluster
while() {
   my \$joining = list_instances_by_filter( 'vtm-joining' );

   if( !scalar( keys( %{\$joining} ) ) ) {
      # No current joiners, we should join
      if( !tag( 'add', 'vtm-joining' ) ) {
         print STDERR "ERROR: Failed to add cluster join tag to instance\n";
         exit 1;
      }
   } else {
      sleep( 5 );
      next;
   }

   sleep( 20 );

   \$joining = list_instances_by_filter( 'vtm-joining' );

   if( scalar( keys( %{\$joining} ) ) > 1 ) {
      # We clashed with another vTM, remove the joining tag and do a random backoff
      tag( 'remove', 'vtm-joining' );
      sleep( 10 + int( rand( 20 ) ) );
   } else {
      last;
   }
}

# Pick a traffic manager to join
my @cluster_members = keys( %{\$cluster} );
my \$target_vtm = \$cluster_members[int( rand( \$cluster_size ) )];
my \$target_address = \$cluster->{\$target_vtm}->{'internal_ip'};
if( !\$target_address ) {
   print STDERR "ERROR: Could not determine IP address for \$target_vtm\n";
   tag( 'remove', 'vtm-joining' );
   exit 1;
} else {
   \$target_address .= ':9090';
}

my %certs = Zeus::ZXTM::Configure::CheckSSLCerts( [ \$target_address ] );
if( !defined \$certs{\$target_address}->{"cert"} ) {
   print STDERR "ERROR: Could not determine IP address for \$target_vtm\n";
   tag( 'remove', 'vtm-joining' );
   exit 1;
}
my \$fprint = \$certs{\$target_address}->{fp};

my @cluster_errs = Zeus::ZXTM::Configure::RegisterWithClusterGetErrors(
                     \$username,
                     \$password,
                     [ \$target_address ],
                     undef,
                     { \$target_address => \$fprint },
                     'yes',
                     undef,
                     'Yes'
                  );

if( scalar( @cluster_errs ) ) {
   print STDERR "ERROR: Failed to join cluster.\n@cluster_errs\n";
   tag( 'remove', 'vtm-joining' );
   exit 1;
}

tag( 'add', 'vtm-cluster' );
tag( 'remove', 'vtm-joining' );

exit 0;

"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create auto-cluster\n')
   sys.exit(1)

try:
   with open('/root/brcd-dm_configure-waf.py', 'w') as f:
      f.write(
r"""#!/usr/bin/python
# Copyright (C) 2016, Brocade Communications Systems. All rights reserved.

import sys
import json
import urllib2
import subprocess
import os

SERVER_URL = 'http://127.0.0.1:9070'
SERVER_BASE_PATH = '/api/af'
USER = 'admin'
PASSWORD = None

try:
   instance = subprocess.check_output("/usr/lib/google-cloud-sdk/bin/gcloud compute project-info describe --format='json'", shell=True).strip()
   metadata = json.loads(instance)
   metadata = metadata['commonInstanceMetadata']['items']
except:
   sys.stderr.write("Unable to get metadata\n")
   sys.exit(1)
for i in metadata:
   if i['key'] == "vtm-pass":
      PASSWORD = i['value']
      break
if PASSWORD is None:
   sys.stderr.write("Unable to retrieve Brocade vTM password\n")
   sys.exit(1)

HOSTNAME = None
try:
   HOSTNAME = subprocess.check_output("hostname", shell=True).strip()
   HOSTNAME = HOSTNAME.rstrip()
except:
   sys.stderr.write("Unable to retrieve instance hostname\n")
   sys.exit(1)
if HOSTNAME is None:
   sys.stderr.write("Unable to retrieve instance hostname\n")
   sys.exit(1)

class ExtRequest(urllib2.Request):

   def __init__(self, url, data=None, headers={}, method=None):
      urllib2.Request.__init__(self, url, data, headers)
      self.__method = method

   def get_method(self):
      if self.__method:
         return self.__method
      return urllib2.Request.get_method(self)

def make_abs_path(path):
   if not path.startswith(SERVER_BASE_PATH):
      return '%s/latest/%s' % (SERVER_BASE_PATH, path)
   return path

def make_request(path, method='GET', body={}, headers={}):
   password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
   password_mgr.add_password(None, SERVER_URL, USER, PASSWORD)
   handler = urllib2.HTTPBasicAuthHandler(password_mgr)
   opener = urllib2.build_opener(handler)
   headers['Content-Type'] = 'application/json'
   request = ExtRequest('%s%s' % (SERVER_URL, make_abs_path(path)), data=json.dumps(body), headers=headers, method=method)
   try:
      response = opener.open(request)
   except urllib2.HTTPError as e:
      sys.stderr.write('Unable to make request')
      sys.exit(1)
   return json.loads(response.read())

def get_latest_available_baseline_version():
   # trigger a baseline download
   response_body = make_request('baselines', 'PATCH', body=dict(action='trigger-baseline-download'))
   # fetch latest available baseline version
   response_body = make_request('baselines')
   baseline_versions = response_body.get('baselines', {}).keys()
   if not baseline_versions:
      return None
   return max(baseline_versions)

def get_available_baseline_categories(baseline_version):
   categories = set()
   response_body = make_request('baselines/%s' % baseline_version)
   for rule in response_body.get('rules', []):
      for category in rule['category']:
         categories.add(category)
   return list(categories)

def main():
   # trigger baseline download
   latest_baseline_version = get_latest_available_baseline_version()
   if not latest_baseline_version:
      sys.stderr.write("no baselines available")
      sys.exit(1)
   # get all available baseline categories
   baseline_categories = get_available_baseline_categories(latest_baseline_version)
   # create new application
   response_body = make_request('applications', 'POST', body=dict(name='BRCD DM Default Application', capability='hyperguard', protected=True))
   new_application_uuid = response_body['__name']
   active_ruleset_uuid = response_body['active_ruleset_uuid']
   # copy currently active ruleset so we can edit it
   response_body = make_request('applications/%s/rulesets/%s' % (new_application_uuid, active_ruleset_uuid), 'COPY', headers={'Destination': make_abs_path('applications/%s/edit' % (new_application_uuid, ))})
   editable_ruleset_path = response_body['__path']
   # enable latest baseline version
   make_request(editable_ruleset_path, 'PUT', body=dict(baseline_version=latest_baseline_version))
   # enable baseline protection handler, set baseline categories and latest baseline version to use
   make_request('%stemplates/BaselineProtectionHandler' % editable_ruleset_path, 'PUT', body=dict(enabled=True, included_categories=baseline_categories))
   # move the edited ruleset back to the application (create a new one)
   response_body = make_request(editable_ruleset_path, 'MOVE', headers={'Destination': make_abs_path('applications/%s/rulesets/' % (new_application_uuid, ))})
   # activate the new ruleset
   make_request('applications/%s' % new_application_uuid, 'PUT', body=dict(active_ruleset_uuid=response_body['__name']))
   # map host to the new application
   new_mapping = [
      {
         "application_uuid": new_application_uuid,
         "hosts": [
            HOSTNAME
         ],
         "prefixes": [
            ""
         ],
      },
   ]
   make_request('application-mapping/_/', 'PUT', body={'mapping': new_mapping})

if __name__ == "__main__":
   main()

"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create configure-waf\n')
   sys.exit(1)

os.chmod("/root/brcd-dm_auto-cluster", 0744)
os.chmod("/root/brcd-dm_configure-waf.py", 0744)
BRCDSTARTUP

ZEUSHOME=/opt/zeus

chmod 744 brcd_startup.py
sudo ./brcd_startup.py
sudo /usr/bin/z-initial-config --replay-from=/root/brcd-dm_replay.txt --noninteractive

sudo grep -v "afm_enabled" /opt/zeus/zxtm/conf/settings.cfg > /opt/zeus/zxtm/conf/settings.cfg
sudo echo "afm_enabled  Yes" >> /opt/zeus/zxtm/conf/settings.cfg

sudo cat > /opt/zeus/zxtm/conf/pools/pool <<POOL
disabled
draining
monitors        Ping
nodes
POOL

sudo cat > /opt/zeus/zxtm/conf/vservers/virtualserver80 <<VSHTTP
address *
enabled Yes
pool    pool
port    80
responserules   "Application Firewall Enforcer"
rules   "Application Firewall Enforcer"
timeout 40
VSHTTP

sudo cat > /opt/zeus/zxtm/conf/vservers/virtualserver443 <<VSHTTPS
address *
enabled Yes
pool    pool
port    443
protocol        https
timeout 40
VSHTTPS

sudo /opt/zeus/zxtm/bin/sysconfig --apply

sleep 20
killall -HUP zeus.configd
sleep 2

sudo /root/brcd-dm_configure-waf.py
sudo /root/brcd-dm_auto-cluster

sudo cat > /opt/zeus/zxtm/conf/rules/return_ok <<RULE
http.sendResponse( "200 OK", "text/html", "OK", "" );
RULE

sudo cat > /opt/zeus/zxtm/conf/vservers/healthcheck <<HEALTH
address *
enabled Yes
pool    discard
port    #BRCD-INTERNAL#HEALTH-PORT#
rules   return_ok
timeout 40
HEALTH

exit 0
'''
VWAF_STARTUP_SCRIPT = VWAF_STARTUP_SCRIPT.replace('#BRCD-INTERNAL#HEALTH-PORT#', str(VTM_HEALTH_PORT))

BACKEND_STARTUP_SCRIPT = ''
if BACKEND_STARTUP_PATH is not None:
   try:
      with open(BACKEND_STARTUP_PATH, 'r') as f:
         BACKEND_STARTUP_SCRIPT= f.read()
         f.close()
   except:
      sys.stderr.write(''.join(['ERROR: Cannot read backend startup script "',
                          BACKEND_STARTUP_PATH, '"\n']))
      sys.exit(1)

BACKEND_SHUTDOWN_SCRIPT = ''
if BACKEND_SHUTDOWN_PATH is not None:
   try:
      with open(BACKEND_SHUTDOWN_PATH, 'r') as f:
         BACKEND_SHUTDOWN_SCRIPT= f.read()
         f.close()
   except:
      sys.stderr.write(''.join(['ERROR: Cannot read backend shutdown script "',
                          BACKEND_SHUTDOWN_PATH, '"\n']))
      sys.exit(1)

###############################################################################
# Create scripts
###############################################################################

versions = {}

try:
   out = subprocess.Popen(['gcloud', 'compute', 'images', 'list',
                           ''.join(['--project=',BRCD_PROJECT])],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
   output, error = out.communicate()

   if out.returncode == 0:
      for line in output.splitlines():
         match = re.match('vtm-(\d+)', line)
         if match:
            available_version = match.group(1)
            versions[available_version] = 1
   else:
      sys.stderr.write(error)
except:
   sys.stderr.write('ERROR: Unable to determine available Brocade vTM versions\n')
   sys.exit(1)

if VERSION not in versions:
   versions_string = ', '.join(versions.keys())
   sys.stderr.write(''.join(['ERROR: No image found for version ', VERSION,
                             '. Available versions: ', versions_string, '\n']))
   sys.exit(1)

show_override = False
if VERSION < '111':
   sys.stderr.write('''
WARNING: This script is not intended for use with Brocade vTM versions earlier
than 11.1, your deployment may not work as expected.

Continue? [Y/N]
'''
   )
   show_override = True
if show_override:
   while True:
      try:
         user_continue = raw_input()
      except NameError:
         sys.stderr.write('This script is intended for use with Python 2.7\n')
         sys.exit(1)

      user_continue = user_continue.strip()
      if re.match('^[yYnN]$', user_continue):
         if user_continue.lower() == 'n':
            sys.exit(0)
         else:
            break
      else:
         sys.stdout.write('Please enter "Y" or "N"\n')

existing_files = []
for file in SCRIPT_FILES:
   if os.path.isfile(file):
      existing_files.append(file)

exists_warn = ''
delete_warn = ''
if len(existing_files):
   exists_list = ',\n'.join(existing_files)
   if not KEEP_FILES:
      delete_warn = ' and deleted'
   exists_warn = ''.join(['\nWARNING: The following files will be overwritten', delete_warn, ':\n', exists_list, '\n'])

action = ''
if NO_DEPLOY:
   action = 'create scripts for'
else:
   action = 'deploy'

# User prompt for continue
sys.stdout.write(
"""Brocade vTM/vWAF Deployment Manager scripts on Google Compute Platform.

This will %(action)s a Brocade vTM/vWAF configuration at version %(version)s in %(zone)s.
%(exists-check)s
Continue? [Y/N]
""" % { 'action': action,
        'version': VERSION,
        'zone': ZONE,
        'exists-check': exists_warn,
      }
)

while True:
   try:
      user_continue = raw_input()
   except NameError:
      sys.stderr.write('This script is intended for use with Python 2.7\n')
      sys.exit(1)

   user_continue = user_continue.strip()
   if re.match('^[yYnN]$', user_continue):
      break
   else:
      sys.stdout.write('Please enter "Y" or "N"\n')

if user_continue.lower() == 'n':
   sys.exit(0)

#-----------------------------------------------------------------------------#
# brcd-config.yaml
#-----------------------------------------------------------------------------#
yaml_imports = """imports:
- path: brcd-master.py
- path: brcd-instance-template.py
- path: brcd-instance-group-manager.py
- path: brcd-autoscaler.py
- path: brcd-firewall.py
- path: brcd-target-pool.py
- path: brcd-health-check.py
- path: brcd-forwarding-rule.py
"""
if CURRENT_NETWORK is None:
   yaml_imports = ''.join([yaml_imports, '- path: brcd-network.py\n'])
try:
   with open('brcd-config.yaml', 'w') as f:
      f.write(
"""%(import)s

resources:
- name: brocade-vtm-vwaf
  type: brcd-master.py
""" % { 'import': yaml_imports }
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-config.yaml\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-master.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-master.py', 'w') as f:
      f.write(
"""def GenerateConfig(unused_context):

   PREFIX = '%(prefix)s'
   NETWORK = '%(network)s'
   NETWORK_REF = '%(network-ref)s'
   SUBNET = '%(subnet)s'
   MACHINE_TYPE = '%(machine-type)s'

   WAF_INSTANCE_TEMPLATE = '%(waf-instance-template)s'
   WAF_TARGET_POOL = '%(waf-target-pool)s'
   WAF_INSTANCE_GROUP_MANAGER = '%(waf-instance-group-manager)s'
   WAF_HEALTH_CHECK = '%(waf-health-check)s'

   ADD_EXTERNAL = %(add-external-ips)s

   ADD_BACKENDS = %(add-backends)s
   BACKEND_INSTANCE_TEMPLATE = '%(backend-instance-template)s'
   BACKEND_INSTANCE_GROUP_MANAGER = '%(backend-instance-group-manager)s'

   REGION = '%(region)s'
   ZONE = '%(zone)s'

   COMPUTE_BASE_URL = '%(compute-base-url)s'
   VTM_IMAGE = '%(vtm-image)s'
   UBUNTU_IMAGE = '%(ubuntu-image)s'
   BRCD_PROJECT = '%(brcd-project)s'
   UBUNTU_PROJECT = '%(ubuntu-project)s'

   SERVICE_ACCOUNT = '%(service-account)s'

   WAF_TAG = '%(waf-tag)s'
   BACKEND_TAG = '%(backend-tag)s'

   WAF_MASTER_PORT = %(waf-master-port)s
   WAF_SLAVE_PORT = %(waf-slave-port)s
   WAF_REST_PORT = %(waf-rest-port)s
   WAF_UPDATER_PORT = %(waf-updater-port)s
   WAF_DECIDER_PORT = %(waf-decider-port)s

   VTM_REST_PORT = %(vtm-rest-port)s
   VTM_CONTROL_PORT = %(vtm-control-port)s
   VTM_ADMIN_PORT = %(vtm-admin-port)s
   VTM_HEALTH_PORT = %(vtm-health-port)s

   VWAF_STARTUP_SCRIPT = r'''
%(vwaf-startup-script)s
'''

   VWAF_SHUTDOWN_SCRIPT = ''

   BACKEND_STARTUP_SCRIPT = '''
%(backend-startup-script)s
'''

   BACKEND_SHUTDOWN_SCRIPT = '''
%(backend-shutdown-script)s
'''


   resources = [
   # New firewall rules are required even if we don't create a network
   {
      'name': ''.join([PREFIX, 'firewall']),
      'type': 'brcd-firewall.py',
      'properties': {
         'network': NETWORK_REF,
         'waf-master-port': WAF_MASTER_PORT,
         'waf-slave-port': WAF_SLAVE_PORT,
         'waf-rest-port': WAF_REST_PORT,
         'waf-updater-port': WAF_UPDATER_PORT,
         'waf-decider-port': WAF_DECIDER_PORT,
         'vtm-rest-port' : VTM_REST_PORT,
         'vtm-control-port': VTM_CONTROL_PORT,
         'vtm-admin-port': VTM_ADMIN_PORT,
         'vtm-health-port': VTM_HEALTH_PORT,
         'waf-tag': WAF_TAG,
         'backend-tag': BACKEND_TAG,
         'add-backends': ADD_BACKENDS,
      },
   },

   # The vWAF instance template, instance group, LB and AS
   {
      'name': WAF_INSTANCE_TEMPLATE,
      'type': 'brcd-instance-template.py',
      'properties': {
         'instance': MACHINE_TYPE,
         'compute-base-url': COMPUTE_BASE_URL,
         'image': VTM_IMAGE,
         'image-project': BRCD_PROJECT,
         'network': NETWORK_REF,
         'tags': WAF_TAG,
         'startup': VWAF_STARTUP_SCRIPT,
         'shutdown': VWAF_SHUTDOWN_SCRIPT,
         'service-account': SERVICE_ACCOUNT,
         'add-external-ips': ADD_EXTERNAL,
      },
   }, {
      'name': WAF_TARGET_POOL,
      'type': 'brcd-target-pool.py',
      'properties': {
         'region': REGION,
         'health-check': WAF_HEALTH_CHECK,
      }
   }, {
      'name': WAF_HEALTH_CHECK,
      'type': 'brcd-health-check.py',
      'properties': {
         'health-port': VTM_HEALTH_PORT,
      }
   }, {
      'name': ''.join([PREFIX, 'fwd-waf']),
      'type': 'brcd-forwarding-rule.py',
      'properties': {
         'target-pool': WAF_TARGET_POOL,
         'region': REGION,
      }
   }, {
      'name': WAF_INSTANCE_GROUP_MANAGER,
      'type': 'brcd-instance-group-manager.py',
      'properties': {
         'instance-prefix': PREFIX,
         'instance-type': 'waf',
         'instance-template': WAF_INSTANCE_TEMPLATE,
         'target-pool': WAF_TARGET_POOL,
         'zone': ZONE,
      },
   }, {
      'name': ''.join([PREFIX, 'as-waf']),
      'type': 'brcd-autoscaler.py',
      'properties': {
         'instance-group-manager': WAF_INSTANCE_GROUP_MANAGER,
         'zone': ZONE,
      }
   },
   ]

   resources_network = [
   {
      'name': NETWORK,
      'type': 'brcd-network.py',
      'properties': {
         'subnet': SUBNET,
      }
   }
   ]

   resources_backends = [
   # The backend (VTM) instance template, instance group, and AS
   {
      'name': BACKEND_INSTANCE_TEMPLATE,
      'type': 'brcd-instance-template.py',
      'properties': {
         'instance': MACHINE_TYPE,
         'compute-base-url': COMPUTE_BASE_URL,
         'image': UBUNTU_IMAGE,
         'image-project': UBUNTU_PROJECT,
         'network': NETWORK_REF,
         'tags': BACKEND_TAG,
         'startup': BACKEND_STARTUP_SCRIPT,
         'shutdown': BACKEND_SHUTDOWN_SCRIPT,
         'service-account': SERVICE_ACCOUNT,
         'add-external-ips': ADD_EXTERNAL,
      },
   }, {
      'name': BACKEND_INSTANCE_GROUP_MANAGER,
      'type': 'brcd-instance-group-manager.py',
      'properties': {
         'instance-prefix': PREFIX,
         'instance-type': 'backend',
         'instance-template': BACKEND_INSTANCE_TEMPLATE,
         'zone': ZONE,
      },
   }, {
      'name': ''.join([PREFIX, 'as-backend']),
      'type': 'brcd-autoscaler.py',
      'properties': {
         'instance-group-manager': BACKEND_INSTANCE_GROUP_MANAGER,
         'zone': ZONE,
      }
   },
   ]

   # Create a network if we are not using an existing one
   if NETWORK_REF.startswith('$'):
      resources.extend(resources_network)

   # Create backends if requested
   if ADD_BACKENDS:
      resources.extend(resources_backends)

   return {'resources': resources}
""" % { 'prefix': PREFIX,
        'network': NETWORK,
        'network-ref': NETWORK_REF,
        'subnet': SUBNET,
        'machine-type': MACHINE_TYPE,
        'waf-instance-template': WAF_INSTANCE_TEMPLATE,
        'waf-target-pool': WAF_TARGET_POOL,
        'waf-instance-group-manager': WAF_INSTANCE_GROUP_MANAGER,
        'waf-health-check': WAF_HEALTH_CHECK,
        'add-external-ips': ADD_EXTERNAL,
        'add-backends': ADD_WEBSERVERS,
        'backend-instance-template': BACKEND_INSTANCE_TEMPLATE,
        'backend-instance-group-manager': BACKEND_INSTANCE_GROUP_MANAGER,
        'compute-base-url': COMPUTE_BASE_URL,
        'region': REGION,
        'zone': ZONE,
        'vtm-image': VTM_IMAGE,
        'brcd-project': BRCD_PROJECT,
        'ubuntu-image': UBUNTU_IMAGE,
        'ubuntu-project': UBUNTU_PROJECT,
        'service-account': SERVICE_ACCOUNT,
        'waf-tag': WAF_TAG,
        'backend-tag': BACKEND_TAG,
        'waf-master-port': WAF_MASTER_PORT,
        'waf-slave-port': WAF_SLAVE_PORT,
        'waf-rest-port': WAF_REST_PORT,
        'waf-updater-port': WAF_UPDATER_PORT,
        'waf-decider-port': WAF_DECIDER_PORT,
        'vtm-rest-port': VTM_REST_PORT,
        'vtm-control-port': VTM_CONTROL_PORT,
        'vtm-admin-port': VTM_ADMIN_PORT,
        'vtm-health-port': VTM_HEALTH_PORT,
        'vwaf-startup-script': VWAF_STARTUP_SCRIPT,
        'backend-startup-script': BACKEND_STARTUP_SCRIPT,
        'backend-shutdown-script': BACKEND_SHUTDOWN_SCRIPT,
      }
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-master.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-instance-template.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-instance-template.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   COMPUTE_BASE_URL = context.properties["compute-base-url"]
   PROJECT = context.env["project"]
   IMAGE_PROJECT = context.properties["image-project"]
   IMAGE = context.properties["image"]
   TAGS = context.properties["tags"]
   STARTUP = context.properties["startup"]
   SHUTDOWN = context.properties["shutdown"]
   SERVICE_ACCOUNT = context.properties["service-account"]
   NETWORK = context.properties["network"]
   ADD_EXTERNAL = context.properties["add-external-ips"]

   network_interfaces = [{'network': NETWORK}]
   if ADD_EXTERNAL:
      network_interfaces[0]['accessConfigs'] = [
         {
            'name': 'External NAT',
            'type': 'ONE_TO_ONE_NAT'
         }
      ]

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.instanceTemplate',
      'properties': {
         'project': PROJECT,
         'properties': {
            'machineType': context.properties["instance"],
            'disks': [{
               'deviceName': 'boot',
               'type': 'PERSISTENT',
               'boot': True,
               'autoDelete': True,
               'initializeParams': {
                  'sourceImage': ''.join([COMPUTE_BASE_URL, 'projects/',
                                          IMAGE_PROJECT, '/global/images/',
                                          IMAGE])
               }
            }],
            'networkInterfaces': network_interfaces,
            'tags': {
               'items': [TAGS]
            },
            'metadata': {
               'items': [
                  {
                     'key': 'startup-script',
                     'value': STARTUP,
                  }, {
                     'key': 'shutdown-script',
                     'value': SHUTDOWN,
                  }
               ]
            },
            'serviceAccounts': [
               {
                  'email': SERVICE_ACCOUNT,
                  'scopes': [
                     'https://www.googleapis.com/auth/compute'
                  ]
               },
            ]
         }
      }
   }]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-instance-template.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-instance-group-manager.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-instance-group-manager.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   try:
      TARGET_POOL = context.properties["target-pool"]
   except:
      TARGET_POOL = ''

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.instanceGroupManager',
      'properties': {
         'zone': context.properties["zone"],
         'baseInstanceName': ''.join([context.properties["instance-prefix"], context.properties["instance-type"]]),
         'targetSize': 1,
         'autoHealingPolicies': [{
            'initialDelaySec': 300
         }],
         'instanceTemplate': ''.join(['$(ref.', context.properties["instance-template"], '.selfLink)']),
      }
   }]

   if len(TARGET_POOL):
      resources[0]['properties']['targetPools'] = [ ''.join(['$(ref.', TARGET_POOL, '.selfLink)']) ]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-instance-group-manager.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-autoscaler.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-autoscaler.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.autoscaler',
      'properties': {
         'target': ''.join(['$(ref.', context.properties["instance-group-manager"], '.selfLink)']),
         'autoscalingPolicy': {
            'minNumReplicas': 1,
            'maxNumReplicas': 3,
            'coolDownPeriodSec': 60,
            'cpuUtilization': {
               'utilizationTarget': 0.9
            },
         },
         'zone': context.properties["zone"],
      }
   }]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-autoscaler.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-network.py
#-----------------------------------------------------------------------------#

if CURRENT_NETWORK is None:
   try:
      with open('brcd-network.py', 'w') as f:
         f.write(
"""
def GenerateConfig(context):

   SUBNET = context.properties["subnet"]

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.network',
      'properties': {
         'IPv4Range': SUBNET,
      }
   }]

   return {'resources': resources}
"""
         )
         f.close()
   except:
      sys.stderr.write('Failed to create brcd-network.py\n')
      sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-firewall.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-firewall.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   WAF_REST_PORT = context.properties['waf-rest-port']

   VTM_REST_PORT = context.properties['vtm-rest-port']
   VTM_CONTROL_PORT = context.properties['vtm-control-port']
   VTM_ADMIN_PORT = context.properties['vtm-admin-port']
   VTM_HEALTH_PORT = context.properties['vtm-health-port']

   WAF_MASTER_PORT = context.properties['waf-master-port']
   WAF_SLAVE_PORT = context.properties['waf-slave-port']
   WAF_UPDATER_PORT = context.properties['waf-updater-port']
   WAF_DECIDER_PORT = context.properties['waf-decider-port']

   WAF_TAG = context.properties["waf-tag"]
   BACKEND_TAG = context.properties["backend-tag"]

   NETWORK = context.properties["network"]

   ADD_BACKENDS = context.properties["add-backends"]

   resources_backend_rules = [{
      'name': ''.join([context.env["name"], "-waftobackend" ]),
      'type': 'compute.v1.firewall',
      'properties': {
         'network': NETWORK,
         'sourceTags': [WAF_TAG],
         'targetTags': [BACKEND_TAG],
         'allowed': [
            {
               'IPProtocol': 'TCP',
               'ports': [80, 443]
            }, {
               'IPProtocol': 'UDP',
               'ports': [80, 443]
            }, {
               'IPProtocol': 'icmp',
            },
         ]
      }
   }, {
      'name': ''.join([context.env["name"], "-backendtowaf" ]),
      'type': 'compute.v1.firewall',
      'properties': {
         'network': NETWORK,
         'sourceTags': [BACKEND_TAG],
         'targetTags': [WAF_TAG],
         'allowed': [
            {
               'IPProtocol': 'TCP',
               'ports': [VTM_REST_PORT, 80, 443]
            }, {
               'IPProtocol': 'UDP',
               'ports': [VTM_REST_PORT, 80, 443]
            },
         ]
      }
   }]

   resources = [{
      'name': ''.join([context.env["name"], "-waftowaf" ]),
      'type': 'compute.v1.firewall',
      'properties': {
         'network': NETWORK,
         'sourceTags': [WAF_TAG],
         'targetTags': [WAF_TAG],
         'allowed': [
            {
               'IPProtocol': 'TCP',
               'ports':
                  [
                     WAF_REST_PORT,
                     WAF_MASTER_PORT,
                     WAF_SLAVE_PORT,
                     WAF_UPDATER_PORT,
                     WAF_DECIDER_PORT,
                     VTM_ADMIN_PORT,
                     VTM_CONTROL_PORT,
                     VTM_REST_PORT,
                  ]
            }, {
               'IPProtocol': 'UDP',
               'ports':
                  [
                     WAF_REST_PORT,
                     WAF_MASTER_PORT,
                     WAF_SLAVE_PORT,
                     WAF_UPDATER_PORT,
                     WAF_DECIDER_PORT,
                     VTM_ADMIN_PORT,
                     VTM_CONTROL_PORT,
                     VTM_REST_PORT,
                  ]
            }, {
               'IPProtocol': 'icmp',
            },
         ]
      }
   }, {
      'name': ''.join([context.env["name"], "-worldtowaf" ]),
      'type': 'compute.v1.firewall',
      'properties': {
         'network': NETWORK,
         'sourceRanges': ['0.0.0.0/0'],
         'targetTags': [WAF_TAG],
         'allowed': [
            {
               'IPProtocol': 'TCP',
               'ports': [80, 443, VTM_HEALTH_PORT]
            }, {
               'IPProtocol': 'UDP',
               'ports': [80, 443]
            }, {
               'IPProtocol': 'icmp',
            },
         ]
      }
   }]

   if ADD_BACKENDS:
      resources.extend(resources_backend_rules)

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-firewall.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-target-pool.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-target-pool.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   HEALTH_CHECK = context.properties["health-check"]

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.targetPool',
      'properties': {
         'healthChecks': [
            ''.join(['$(ref.', HEALTH_CHECK, '.selfLink)'])
         ],
         'region': context.properties["region"],
      }
   }]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-target-pool.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-health-check.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-health-check.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context):

   HEALTH_PORT = context.properties['health-port']

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.httpHealthCheck',
      'properties': {
         'healthyThreshold': 2,
         'unhealthyThreshold': 2,
         'checkIntervalSec': 3,
         'timeoutSec': 3,
         'port': HEALTH_PORT,
      }
   }]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-health-check.py\n')
   sys.exit(1)

#-----------------------------------------------------------------------------#
# brcd-forwarding-rule.py
#-----------------------------------------------------------------------------#

try:
   with open('brcd-forwarding-rule.py', 'w') as f:
      f.write(
"""
def GenerateConfig(context): 

   resources = [{
      'name': context.env["name"],
      'type': 'compute.v1.forwardingRule',
      'properties': {
         'target': ''.join(['$(ref.', context.properties["target-pool"], '.selfLink)']),
         'region': context.properties["region"],
      }
   }]

   return {'resources': resources}
"""
      )
      f.close()
except:
   sys.stderr.write('Failed to create brcd-forwarding-rule.py\n')
   sys.exit(1)

###############################################################################
# Deploy, delete and exit
###############################################################################

deployment_name = ''.join([PREFIX, 'deployment'])

if NO_DEPLOY:
   sys.stdout.write(
"""

Scripts generated. To deploy your Brocade vTM/vWAF configuration, run:
  gcloud deployment-manager deployments create %(dm-name)s --config brcd-config.yaml

""" % { 'dm-name': deployment_name }
   )
else:
   try:
      out = subprocess.Popen(['gcloud', 'deployment-manager', 'deployments',
                              'create', deployment_name, '--config',
                              'brcd-config.yaml'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)

      output, error = out.communicate()

      if out.returncode != 0:
         sys.stdout.write(output)
      else:
         sys.stdout.write(error)
   except:
      sys.stderr.write('ERROR: Unable to launch gcloud deployment\n')

# Delete the files we have created
if not KEEP_FILES:
   for file in SCRIPT_FILES:
      if os.path.isfile(file):
         try:
            os.remove(file)
         except:
            sys.stderr.write( 'ERROR: Could not delete %s\n' % ( file ) )

sys.exit(0)