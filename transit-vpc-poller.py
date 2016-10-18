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
from xml.dom import minidom
import ast
import logging
import datetime, sys, json, urllib2, urllib, re
log = logging.getLogger()
log.setLevel(logging.INFO)

bucket_name='%BUCKET_NAME%'
bucket_prefix='%PREFIX%'

#VGW tags come in the format of [{"Key": "Tag1", "Value":"Tag1value"},{"Key":"Tag2","Value":"Tag2value"}]
#This function converts the array of Key/Value dicts to a single tag dictionary
def getTags(vgwTags):
  tags = {}
  for subTag in vgwTags:
    tags[subTag['Key']] = subTag['Value']
  return tags

#This function adds a <transit_vpc_config /> block to an existing XML doc and returns the new XML
def updateConfigXML(xml, config, vgwTags, account_id, csr_number):
  xmldoc=minidom.parseString(xml)
  #Create TransitVPC config xml block
  transitConfig= xmldoc.createElement("transit_vpc_config")
  #Create Account ID xml block
  newXml = xmldoc.createElement("account_id")
  newXml.appendChild(xmldoc.createTextNode(account_id))
  transitConfig.appendChild(newXml)

  #Create VPN Endpoint xml block
  newXml = xmldoc.createElement("vpn_endpoint")
  newXml.appendChild(xmldoc.createTextNode(csr_number))
  transitConfig.appendChild(newXml)

  #Create status xml block (create = tagged to create spoke, delete = tagged as spoke, but not with the correct spoke tag value)
  newXml = xmldoc.createElement("status")
  if vgwTags[config['HUB_TAG']] == config['HUB_TAG_VALUE']:
    newXml.appendChild(xmldoc.createTextNode("create"))
  else:
    newXml.appendChild(xmldoc.createTextNode("delete"))
  transitConfig.appendChild(newXml)

  #Configure preferred transit VPC path
  newXml = xmldoc.createElement("preferred_path")
  newXml.appendChild(xmldoc.createTextNode(vgwTags.get(config['PREFERRED_PATH_TAG'], 'none')))
  transitConfig.appendChild(newXml)

  #Add transit config to XML
  xmldoc.childNodes[0].appendChild(transitConfig)
  return str(xmldoc.toxml())

#This function determines whether or not Anonymous data should be send and, if so, sends it
def sendAnonymousData(config, vgwTags, region_id, vpn_connections):
  #Code to send anonymous data if enabled
  if config['SENDDATA'] == "Yes":
    log.debug("Sending Anonymous Data")
    dataDict = {}    
    postDict = {}
    dataDict['region'] = region_id
    dataDict['vpn_connections'] = vpn_connections
    if vgwTags[config['HUB_TAG']] == config['HUB_TAG_VALUE']:
      dataDict['status'] = "create"  
    else:
      dataDict['status'] = "delete"
    dataDict['preferred_path'] = vgwTags.get(config['PREFERRED_PATH_TAG'], 'none')
    dataDict['version'] = '3'
    postDict['Data'] = dataDict
    postDict['TimeStamp'] = str(datetime.datetime.now())
    postDict['Solution'] = 'SO0001'
    postDict['UUID'] = config['UUID']
    # API Gateway URL to make HTTP POST call
    url = 'https://metrics.awssolutionsbuilder.com/generic'
    data=json.dumps(postDict)
    log.info(data)
    headers = {'content-type': 'application/json'}
    req = urllib2.Request(url, data, headers)
    rsp = urllib2.urlopen(req)
    rspcode = rsp.getcode()
    content = rsp.read()
    log.debug("Response from APIGateway: %s, %s", rspcode, content)


def lambda_handler(event, context):
  #Figure out the account number by parsing this function's ARN
  account_id = re.findall(':(\d+):', context.invoked_function_arn)[0]
  #Retrieve Transit VPC configuration from transit_vpn_config.txt
  s3=boto3.client('s3', config=Config(signature_version='s3v4'))
  log.info('Getting config file %s/%s%s',bucket_name, bucket_prefix, 'transit_vpc_config.txt')
  config=ast.literal_eval(s3.get_object(Bucket=bucket_name,Key=bucket_prefix+'transit_vpc_config.txt')['Body'].read())

  log.info('Retrieved IP of transit VPN gateways: %s, %s',config['EIP1'], config['EIP2'])
  # use this variable to determine if a VGW has been processed so we will only process one VGW per run (one per minute)
  processed_vgw = False 
  #Get list of regions so poller can look for VGWs in all regions
  ec2=boto3.client('ec2',region_name='us-east-1')
  regions=ec2.describe_regions()
  for region in regions['Regions']:
    #Get region name for the current region
    region_id=region['RegionName']
    log.debug('Checking region: %s',region_id)
    #Create EC2 connection to this region to get list of VGWs
    ec2=boto3.client('ec2',region_name=region_id)
    #Get list of VGWs that are available and tagged for Transit VPC
    #vgws=ec2.describe_vpn_gateways(Filters=[
    #  {'Name':'state','Values':['available', 'attached', 'detached']},
    #  {'Name': 'tag-key', 'Values': [config['HUB_TAG']]}
    #])
    #Get list of all VGWs in the region
    vgws=ec2.describe_vpn_gateways(Filters=[
      {'Name':'state','Values':['available', 'attached', 'detached']}
    ])
    #Get list of Transit VPC tagged VPN connections in the region as well
    vpns=ec2.describe_vpn_connections(Filters=[
      {'Name':'state','Values':['available','pending','deleting']},
      {'Name':'tag:'+config['HUB_TAG'],'Values':[config['HUB_TAG_VALUE']]}
    ])
    #Process all the VGWs in the region
    for vgw in vgws['VpnGateways']:
      #Check to see if the VGW has tags, if not, then we should skip it
      if vgw.get('Tags', '') == '':
        continue

      #Put all of the VGW tags into a dict for easier processing
      vgwTags = getTags(vgw['Tags'])

      #Configure HUB_TAG if it is not set already (for untagged VGWs)
      vgwTags[config['HUB_TAG']] = vgwTags.get(config['HUB_TAG'], '')

      #Determine if VGW is tagged as a spoke
      spoke_vgw = False
      if vgwTags[config['HUB_TAG']] == config['HUB_TAG_VALUE']:
        spoke_vgw = True

      #Check to see if the VGW already has Transit VPC VPN Connections
      vpn_existing=False
      for vpn in vpns['VpnConnections']:
        if vpn['VpnGatewayId']==vgw['VpnGatewayId']:
          vpn_existing=True
          break

      #Need to create VPN connections if this is a spoke VGW and no VPN connections already exist
      if spoke_vgw and not vpn_existing:
        log.info('Found a new VGW (%s) which needs VPN connections.', vgw['VpnGatewayId'])
        #Create Customer Gateways (will create CGWs if they do not exist, otherwise, the API calls are ignored)
        log.debug('Creating Customer Gateways with IP %s, %s', config['EIP1'], config['EIP2'])
        cg1=ec2.create_customer_gateway(Type='ipsec.1',PublicIp=config['EIP1'],BgpAsn=config['BGP_ASN'])
        ec2.create_tags(Resources=[cg1['CustomerGateway']['CustomerGatewayId']], Tags=[{'Key': 'Name','Value': 'Transit VPC Endpoint1' }])
        cg2=ec2.create_customer_gateway(Type='ipsec.1',PublicIp=config['EIP2'],BgpAsn=config['BGP_ASN'])
        ec2.create_tags(Resources=[cg2['CustomerGateway']['CustomerGatewayId']], Tags=[{'Key': 'Name','Value': 'Transit VPC Endpoint2' }])
        log.info('Created Customer Gateways: %s, %s',cg1['CustomerGateway']['CustomerGatewayId'], cg2['CustomerGateway']['CustomerGatewayId'])
  
        #Create and tag first VPN connection
        vpn1=ec2.create_vpn_connection(Type='ipsec.1',CustomerGatewayId=cg1['CustomerGateway']['CustomerGatewayId'],VpnGatewayId=vgw['VpnGatewayId'],Options={'StaticRoutesOnly':False})
        ec2.create_tags(Resources=[vpn1['VpnConnection']['VpnConnectionId']], 
            Tags=[
                {'Key': 'Name','Value': vgw['VpnGatewayId']+'-to-Transit-VPC CSR1' },
                {'Key': config['HUB_TAG'],'Value': config['HUB_TAG_VALUE'] },
                {'Key': 'transitvpc:endpoint','Value': 'CSR1' }
            ])
        #Create and tag second VPN connection
        vpn2=ec2.create_vpn_connection(Type='ipsec.1',CustomerGatewayId=cg2['CustomerGateway']['CustomerGatewayId'],VpnGatewayId=vgw['VpnGatewayId'],Options={'StaticRoutesOnly':False})
        ec2.create_tags(Resources=[vpn2['VpnConnection']['VpnConnectionId']],
                    Tags=[
                {'Key': 'Name','Value': vgw['VpnGatewayId']+'-to-Transit-VPC CSR2' },
                {'Key': config['HUB_TAG'],'Value': config['HUB_TAG_VALUE'] },
                {'Key': 'transitvpc:endpoint','Value': 'CSR2' }
            ])
        log.info('Created VPN connections: %s, %s', vpn1['VpnConnection']['VpnConnectionId'], vpn2['VpnConnection']['VpnConnectionId'])
  	
        #Retrieve VPN configuration
        vpn_config1=ec2.describe_vpn_connections(VpnConnectionIds=[vpn1['VpnConnection']['VpnConnectionId']])
        vpn_config1=vpn_config1['VpnConnections'][0]['CustomerGatewayConfiguration']
	    #Update VPN configuration XML with transit VPC specific configuration info for this connection
        vpn_config1=updateConfigXML(vpn_config1, config, vgwTags, account_id, 'CSR1')
        #Put CSR1 config in S3
        s3.put_object(
              Body=str.encode(vpn_config1),
              Bucket=bucket_name,
              Key=bucket_prefix+'CSR1/'+region_id+'-'+vpn1['VpnConnection']['VpnConnectionId']+'.conf',
              ACL='bucket-owner-full-control',
              ServerSideEncryption='aws:kms',
              SSEKMSKeyId=config['KMS_KEY']
              )
        vpn_config2=ec2.describe_vpn_connections(VpnConnectionIds=[vpn2['VpnConnection']['VpnConnectionId']])
        vpn_config2=vpn_config2['VpnConnections'][0]['CustomerGatewayConfiguration']
	    #Update VPN configuration XML with transit VPC specific configuration info for this connection
        vpn_config2=updateConfigXML(vpn_config2, config, vgwTags, account_id, 'CSR2')
        #Put CSR2 config in S3
        s3.put_object(
	      Body=str.encode(vpn_config2),
	      Bucket=bucket_name,
	      Key=bucket_prefix+'CSR2/'+region_id+'-'+vpn2['VpnConnection']['VpnConnectionId']+'.conf',
	      ACL='bucket-owner-full-control',
	      ServerSideEncryption='aws:kms',
	      SSEKMSKeyId=config['KMS_KEY']
    	)
        log.debug('Pushed VPN configurations to S3...')
        processed_vgw = True
        sendAnonymousData(config, vgwTags, region_id, 2)

      #Need to delete VPN connections if this is no longer a spoke VPC (tagged for spoke, but tag != spoke tag value) but Transit VPC connections exist
      if not spoke_vgw and vpn_existing:
        log.info('Found old VGW (%s) with VPN connections to remove.', vgw['VpnGatewayId'])
        #We need to go through the region's VPN connections to find the ones to delete
        for vpn in vpns['VpnConnections']:
          if vpn['VpnGatewayId']==vgw['VpnGatewayId']:
            #Put the VPN tags into a dict for easier processing
            vpnTags = getTags(vpn['Tags'])
            if vpnTags['transitvpc:endpoint'] == 'CSR1':
              csrNum = '1'
            else:
              csrNum = '2'
            #Need to get VPN configuration to remove from CSR
            vpn_config=vpn['CustomerGatewayConfiguration']
            #Update VPN configuration XML with transit VPC specific configuration info for this connection
            vpn_config=updateConfigXML(vpn_config, config, vgwTags, account_id, vpnTags['transitvpc:endpoint'])
            s3.put_object(
                  Body=str.encode(vpn_config),
                  Bucket=bucket_name,
                  Key=bucket_prefix+'CSR'+csrNum+'/'+region_id+'-'+vpn['VpnConnectionId']+'.conf',
                  ACL='bucket-owner-full-control',
                  ServerSideEncryption='aws:kms',
                  SSEKMSKeyId=config['KMS_KEY']
            )
            log.debug('Pushed CSR%s configuration to S3.', csrNum)
            #now we need to delete the VPN connection
            ec2.delete_vpn_connection(VpnConnectionId=vpn['VpnConnectionId'])
            log.info('Deleted VPN connection (%s) to CSR%s', vpn['VpnConnectionId'], csrNum)
            #Attempt to clean up the CGW. This will only succeed if the CGW has no VPN connections are deleted
            try:
                ec2.delete_customer_gateway(CustomerGatewayId=vpn['CustomerGatewayId'])
                log.info("Cleaned up %s since it has no VPN connections left", vpn['CustomerGatewayId'])
            except:
                log.debug("%s still has existing VPN connections", vpn['CustomerGatewayId'])
            sendAnonymousData(config, vgwTags, region_id, 1)

      # if a VGW has been processed, then we need to break out of VGW processing
      if processed_vgw:
        break
    # if a VGW has been processed, then we need to break out of region processing
    if processed_vgw:
      break
