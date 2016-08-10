######################################################################################################################
#  Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance        #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://aws.amazon.com/asl/                                                                                    #
#                                                                                                                    #   
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import boto3
from botocore.client import Config
import paramiko
from xml.dom import minidom
import ast
import time
import os
import string
import logging
log = logging.getLogger()
log.setLevel(logging.INFO)

config_file='transit_vpc_config.txt'
endpoint_url = {
  "us-east-1" : "https://s3.amazonaws.com",
  "us-west-1" : "https://s3-us-west-1.amazonaws.com",
  "us-west-2" : "https://s3-us-west-2.amazonaws.com",
  "eu-west-1" : "https://s3-eu-west-1.amazonaws.com",
  "eu-central-1" : "https://s3-eu-central-1.amazonaws.com",
  "ap-northeast-1" : "https://s3-ap-northeast-1.amazonaws.com",
  "ap-northeast-2" : "https://s3-ap-northeast-2.amazonaws.com",
  "ap-southeast-1" : "https://s3-ap-southeast-1.amazonaws.com",
  "ap-southeast-2" : "https://s3-ap-southeast-2.amazonaws.com",
  "sa-east-1" : "https://s3-sa-east-1.amazonaws.com"
}

#Logic to determine when the prompt has been discovered
def prompt(chan):
    buff = ''
    while not buff.endswith('#'):
        resp = chan.recv(9999)
        buff += resp
        #log.debug("%s",resp)
    return buff

# Logic to figure out the next availble tunnel
def getNextTunnelId(ssh):
    log.info('Start getNextTunnelId')
    ssh.send('term len 0\n')
    log.debug("%s",prompt(ssh))
    ssh.send('config t\n')
    log.debug("%s",prompt(ssh))
    ssh.send('do show int summary | include Tunnel\n')
    output = prompt(ssh)
    log.debug("%s",output)
    ssh.send('exit\n')
    log.debug("%s",prompt(ssh))
    lastTunnelNum=''
    for line in output.split('\n'):
        line=line.replace('* Tunnel','Tunnel')
        log.debug("%s",line)
        if line.strip()[:6] == 'Tunnel':
            lastTunnelNum = line.strip().partition(' ')[0].replace('Tunnel','')

    if lastTunnelNum == '':
        return 1
    return int(lastTunnelNum) + 1

def pushConfig(ssh,config):
    #log.info("Starting to push config")
    #ssh.send('term len 0\n')
    #prompt(ssh)
    ssh.send('config t\n')
    log.debug("%s",prompt(ssh))
    stime = time.time()
    for line in config:
	ssh.send(line+'\n')
        log.debug("%s",prompt(ssh))
    ssh.send('exit\n')
    log.debug("%s",prompt(ssh))
    log.debug("   --- %s seconds ---", (time.time() - stime))
    log.info("Saving config!")
    ssh.send('copy run start\n\n\n\n\n')
    log.info("%s",prompt(ssh))
    log.info("Update complete!")

def getBucketPrefix(bucket_name, bucket_key):
    #Figure out prefix from known bucket_name and bucket_key
    bucket_prefix = '/'.join(bucket_key.split('/')[:-2])
    if len(bucket_prefix) > 0:
        bucket_prefix += '/'
    return bucket_prefix

def getTransitConfig(bucket_name, bucket_prefix, s3_url, config_file):
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading config file: %s/%s/%s%s", s3_url, bucket_name, bucket_prefix,config_file)
    return ast.literal_eval(s3.get_object(Bucket=bucket_name,Key=bucket_prefix+config_file)['Body'].read())

def putTransitConfig(bucket_name, bucket_prefix, s3_url, config_file, config):
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Uploading new config file: %s/%s/%s%s", s3_url,bucket_name, bucket_prefix,config_file)
    s3.put_object(Bucket=bucket_name,Key=bucket_prefix+config_file,Body=str(config))

def downloadPrivateKey(bucket_name, bucket_prefix, s3_url, prikey):
    if os.path.exists('/tmp/'+prikey):
        os.remove('/tmp/'+prikey)
    s3=boto3.client('s3', endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    log.info("Downloading private key: %s/%s/%s%s",s3_url, bucket_name, bucket_prefix, prikey)
    s3.download_file(bucket_name,bucket_prefix+prikey, '/tmp/'+prikey)

def create_cisco_config(bucket_name, bucket_key, s3_url, bgp_asn, ssh):
    log.info("Processing %s/%s", bucket_name, bucket_key)

    s3=boto3.client('s3',endpoint_url=s3_url,
      config=Config(s3={'addressing_style': 'virtual'}, signature_version='s3v4'))
    config=s3.get_object(Bucket=bucket_name,Key=bucket_key)

    xmldoc=minidom.parseString(config['Body'].read())
    vpn_connection=xmldoc.getElementsByTagName('vpn_connection')[0]
    vpn_connection_id=vpn_connection.attributes['id'].value
    customer_gateway_id=vpn_connection.getElementsByTagName("customer_gateway_id")[0].firstChild.data
    vpn_gateway_id=vpn_connection.getElementsByTagName("vpn_gateway_id")[0].firstChild.data
    vpn_connection_type=vpn_connection.getElementsByTagName("vpn_connection_type")[0].firstChild.data
        
    tunnelId=getNextTunnelId(ssh)
    log.info("Configuring %s with tunnel #%s and #%s.",vpn_connection_id, tunnelId, tunnelId+1)
    config_text = ['ip vrf {}'.format(vpn_connection_id)]
    config_text.append(' rd {}:{}'.format(bgp_asn, tunnelId))
    config_text.append(' route-target export {}:0'.format(bgp_asn))
    config_text.append(' route-target import {}:0'.format(bgp_asn))
    config_text.append('exit')
    
    for ipsec_tunnel in vpn_connection.getElementsByTagName("ipsec_tunnel"):
        customer_gateway=ipsec_tunnel.getElementsByTagName("customer_gateway")[0]
        customer_gateway_tunnel_outside_address=customer_gateway.getElementsByTagName("tunnel_outside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
        customer_gateway_tunnel_inside_address_ip_address=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
        customer_gateway_tunnel_inside_address_network_mask=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_mask")[0].firstChild.data
        customer_gateway_tunnel_inside_address_network_cidr=customer_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_cidr")[0].firstChild.data
        customer_gateway_bgp_asn=customer_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("asn")[0].firstChild.data
        customer_gateway_bgp_hold_time=customer_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("hold_time")[0].firstChild.data
        
        vpn_gateway=ipsec_tunnel.getElementsByTagName("vpn_gateway")[0]
        vpn_gateway_tunnel_outside_address=vpn_gateway.getElementsByTagName("tunnel_outside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
        vpn_gateway_tunnel_inside_address_ip_address=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("ip_address")[0].firstChild.data
        vpn_gateway_tunnel_inside_address_network_mask=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_mask")[0].firstChild.data
        vpn_gateway_tunnel_inside_address_network_cidr=vpn_gateway.getElementsByTagName("tunnel_inside_address")[0].getElementsByTagName("network_cidr")[0].firstChild.data
        vpn_gateway_bgp_asn=vpn_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("asn")[0].firstChild.data
        vpn_gateway_bgp_hold_time=vpn_gateway.getElementsByTagName("bgp")[0].getElementsByTagName("hold_time")[0].firstChild.data
        
        ike=ipsec_tunnel.getElementsByTagName("ike")[0]
        ike_authentication_protocol=ike.getElementsByTagName("authentication_protocol")[0].firstChild.data
        ike_encryption_protocol=ike.getElementsByTagName("encryption_protocol")[0].firstChild.data
        ike_lifetime=ike.getElementsByTagName("lifetime")[0].firstChild.data
        ike_perfect_forward_secrecy=ike.getElementsByTagName("perfect_forward_secrecy")[0].firstChild.data
        ike_mode=ike.getElementsByTagName("mode")[0].firstChild.data
        ike_pre_shared_key=ike.getElementsByTagName("pre_shared_key")[0].firstChild.data
        
        ipsec=ipsec_tunnel.getElementsByTagName("ipsec")[0]
        ipsec_protocol=ipsec.getElementsByTagName("protocol")[0].firstChild.data
        ipsec_authentication_protocol=ipsec.getElementsByTagName("authentication_protocol")[0].firstChild.data
        ipsec_encryption_protocol=ipsec.getElementsByTagName("encryption_protocol")[0].firstChild.data
        ipsec_lifetime=ipsec.getElementsByTagName("lifetime")[0].firstChild.data
        ipsec_perfect_forward_secrecy=ipsec.getElementsByTagName("perfect_forward_secrecy")[0].firstChild.data
        ipsec_mode=ipsec.getElementsByTagName("mode")[0].firstChild.data
        ipsec_clear_df_bit=ipsec.getElementsByTagName("clear_df_bit")[0].firstChild.data
        ipsec_fragmentation_before_encryption=ipsec.getElementsByTagName("fragmentation_before_encryption")[0].firstChild.data
        ipsec_tcp_mss_adjustment=ipsec.getElementsByTagName("tcp_mss_adjustment")[0].firstChild.data
        ipsec_dead_peer_detection_interval=ipsec.getElementsByTagName("dead_peer_detection")[0].getElementsByTagName("interval")[0].firstChild.data
        ipsec_dead_peer_detection_retries=ipsec.getElementsByTagName("dead_peer_detection")[0].getElementsByTagName("retries")[0].firstChild.data

        config_text.append('crypto keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId))
        config_text.append('  local-address GigabitEthernet1')
        config_text.append('  pre-shared-key address {} key {}'.format(vpn_gateway_tunnel_outside_address, ike_pre_shared_key))
        config_text.append('exit')
        
        config_text.append('crypto isakmp profile isakmp-{}-{}'.format(vpn_connection_id,tunnelId))
        config_text.append('  local-address GigabitEthernet1')
        config_text.append('  match identity address {}'.format(vpn_gateway_tunnel_outside_address))
        config_text.append('  keyring keyring-{}-{}'.format(vpn_connection_id,tunnelId))
        config_text.append('exit')
            
        config_text.append('interface Tunnel{}'.format(tunnelId))
        config_text.append('  ip vrf forwarding {}'.format(vpn_connection_id))
        config_text.append('  ip address {} 255.255.255.252'.format(customer_gateway_tunnel_inside_address_ip_address))
        config_text.append('  ip virtual-reassembly')
        config_text.append('  tunnel source GigabitEthernet1')
        config_text.append('  tunnel destination {} '.format(vpn_gateway_tunnel_outside_address))
        config_text.append('  tunnel mode ipsec ipv4')
        config_text.append('  tunnel protection ipsec profile ipsec-vpn-aws')
        config_text.append('  ip tcp adjust-mss 1387')
        config_text.append('  no shutdown')
        config_text.append('exit')
            
        config_text.append('router bgp {}'.format(customer_gateway_bgp_asn))
        config_text.append('address-family ipv4 vrf {}'.format(vpn_connection_id))
        config_text.append('  neighbor {} remote-as {}'.format(vpn_gateway_tunnel_inside_address_ip_address, vpn_gateway_bgp_asn))
        config_text.append('  neighbor {} timers 10 30 30'.format(vpn_gateway_tunnel_inside_address_ip_address))
        config_text.append('  neighbor {} activate'.format(vpn_gateway_tunnel_inside_address_ip_address))
        config_text.append('  neighbor {} as-override'.format(vpn_gateway_tunnel_inside_address_ip_address))
        config_text.append('  neighbor {} soft-reconfiguration inbound'.format(vpn_gateway_tunnel_inside_address_ip_address))
        config_text.append('exit')
        config_text.append('exit')
        
        tunnelId+=1
        
    log.info("Conversion complete")
    return config_text

def lambda_handler(event, context):
    record=event['Records'][0]
    bucket_name=record['s3']['bucket']['name']
    bucket_key=record['s3']['object']['key']
    bucket_region=record['awsRegion']
    bucket_prefix=getBucketPrefix(bucket_name, bucket_key)
    log.info("Getting config")
    stime = time.time()
    config = getTransitConfig(bucket_name, bucket_prefix, endpoint_url[bucket_region], config_file)
    if 'CSR1' in bucket_key:
        csr_ip=config['PIP1']
	#csr_pwd=config['PASSWORD']
    else:
        csr_ip=config['PIP2']
	#csr_pwd=config['PASSWORD']
    log.info("--- %s seconds ---", (time.time() - stime))
    #Download private key file from secure S3 bucket
    downloadPrivateKey(bucket_name, bucket_prefix, endpoint_url[bucket_region], config['PRIVATE_KEY'])
    log.info("Reading downloaded private key into memory.")
    k = paramiko.RSAKey.from_private_key_file("/tmp/"+config['PRIVATE_KEY'])
    #Delete the temp copy of the private key
    os.remove("/tmp/"+config['PRIVATE_KEY'])
    log.info("Deleted downloaded private key.")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    log.info("Connecting to %s", csr_ip)
    stime = time.time()
    try:
      c.connect( hostname = csr_ip, username = config['USER_NAME'], pkey = k )
      PubKeyAuth=True
    except paramiko.ssh_exception.AuthenticationException:
      log.error("PubKey Authentication Failed! Connecting with password")
      c.connect( hostname = csr_ip, username = config['USER_NAME'], password = config['PASSWORD'] )
      PubKeyAuth=False
    log.info("--- %s seconds ---", (time.time() - stime))
    log.info("Connected to %s",csr_ip)
    ssh = c.invoke_shell()
    log.debug("%s",prompt(ssh))
 # Legacy for configuring pubkey auth if only password auth worked
 #   if not PubKeyAuth:
 #     stime = time.time()
 #     log.info("PubKeyAuth didn't work, time to configure it!")
 #     config['PASSWORD']=configSshPubKeyAuth(ssh,config)
 #     putTransitConfig(bucket_name,bucket_prefix, endpoint_url[bucket_region], config_file, config)
 #     log.info("--- %s seconds ---", (time.time() - stime))
    log.info("Creating config.")
    stime = time.time()
    csr_config = create_cisco_config(bucket_name, bucket_key, endpoint_url[bucket_region], config['BGP_ASN'], ssh)
    log.info("--- %s seconds ---", (time.time() - stime))
    log.info("Pushing config.")
    stime = time.time()
    pushConfig(ssh,csr_config)
    log.info("--- %s seconds ---", (time.time() - stime))
    ssh.close()
    

    return
    {
        'message' : "Script execution completed. See Cloudwatch logs for complete output"
    }
