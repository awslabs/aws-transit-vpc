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
import ast
import logging
import datetime, sys, json, urllib2, urllib
log = logging.getLogger()
log.setLevel(logging.INFO)


bucket_region='%REGION%'
bucket_name='%BUCKET_NAME%'
bucket_prefix='%PREFIX%'

def lambda_handler(event, context):
  #Check to see if the event is related to a VGW, otherwise ignore
  #if "vgw" not in event['detail']['requestParameters']['resourcesSet']['items'][0]['resourceId']:
  #    print("Not a VGW event.  Exiting function")
  #    return
  
  #Retrieve EIP of transit VPN gateways from transit_vpn_config.txt
  #s3=boto3.client('s3',region_name=bucket_region)

  s3=boto3.client('s3')
  log.info('Getting config file %s/%s%s',bucket_name, bucket_prefix, 'transit_vpc_config.txt')
  config=ast.literal_eval(s3.get_object(Bucket=bucket_name,Key=bucket_prefix+'transit_vpc_config.txt')['Body'].read())

  log.info('Retrieved IP of transit VPN gateways: %s, %s',config['EIP1'], config['EIP2'])
  
  ec2=boto3.client('ec2',region_name='us-east-1')
  regions=ec2.describe_regions()
  for region in regions['Regions']:
  
    region_id=region['RegionName']
    print('Checking region: '+region_id)
    ec2=boto3.client('ec2',region_name=region_id)
  
    vgws=ec2.describe_vpn_gateways(Filters=[
      {'Name':'attachment.state','Values':['attached','attaching','detaching']},
      {'Name':'state','Values':['available','pending','deleting']},
      {'Name':'tag:'+config['HUB_TAG'],'Values':[config['HUB_TAG_VALUE']]}
    ])
    vpns=ec2.describe_vpn_connections(Filters=[
      {'Name':'state','Values':['available','pending','deleting']}
    ])
    for vgw in vgws['VpnGateways']:
  
      #Make sure the VGW is not already connected to a VPN
      vpn_existing=False
      for vpn in vpns['VpnConnections']:
        if vpn['VpnGatewayId']==vgw['VpnGatewayId']:
          vpn_existing=True
          break
      if vpn_existing==False:
  
        log.info('Found a new VGW to process: %s', vgw['VpnGatewayId'])
  
        #Create Customer Gateways
        log.info('Creating Customer Gateways with IP %s, %s', config['EIP1'], config['EIP2'])
        cg1=ec2.create_customer_gateway(Type='ipsec.1',PublicIp=config['EIP1'],BgpAsn=config['BGP_ASN'])
        ec2.create_tags(Resources=[cg1['CustomerGateway']['CustomerGatewayId']], Tags=[{'Key': 'Name','Value': 'Transit VPC Endpoint1' }])
        cg2=ec2.create_customer_gateway(Type='ipsec.1',PublicIp=config['EIP2'],BgpAsn=config['BGP_ASN'])
        ec2.create_tags(Resources=[cg2['CustomerGateway']['CustomerGatewayId']], Tags=[{'Key': 'Name','Value': 'Transit VPC Endpoint2' }])
        log.info('Created Customer Gateways: %s, %s',cg1['CustomerGateway']['CustomerGatewayId'], cg2['CustomerGateway']['CustomerGatewayId'])
  
        #Create VPN connection
        vpn1=ec2.create_vpn_connection(Type='ipsec.1',CustomerGatewayId=cg1['CustomerGateway']['CustomerGatewayId'],VpnGatewayId=vgw['VpnGatewayId'],Options={'StaticRoutesOnly':False})
        ec2.create_tags(Resources=[vpn1['VpnConnection']['VpnConnectionId']], Tags=[{'Key': 'Name','Value': vgw['VpnGatewayId']+'-to-Transit-VPC VPN1' }])
        vpn2=ec2.create_vpn_connection(Type='ipsec.1',CustomerGatewayId=cg2['CustomerGateway']['CustomerGatewayId'],VpnGatewayId=vgw['VpnGatewayId'],Options={'StaticRoutesOnly':False})
        ec2.create_tags(Resources=[vpn2['VpnConnection']['VpnConnectionId']], Tags=[{'Key': 'Name','Value': vgw['VpnGatewayId']+'-to-Transit-VPC VPN2' }])
        log.info('Created VPN connections: %s, %s', vpn1['VpnConnection']['VpnConnectionId'], vpn2['VpnConnection']['VpnConnectionId'])
  
        #Retrieve VPN configuration
        vpn_config1=ec2.describe_vpn_connections(VpnConnectionIds=[vpn1['VpnConnection']['VpnConnectionId']])
        vpn_config1=vpn_config1['VpnConnections'][0]['CustomerGatewayConfiguration']
        s3.put_object(
	    Body=str.encode(vpn_config1),
	    Bucket=bucket_name,
	    Key=bucket_prefix+'CSR1/'+region_id+'-'+vpn1['VpnConnection']['VpnConnectionId']+'.conf',
	    ACL='bucket-owner-full-control',
	    ServerSideEncryption='AES256'
	)
        vpn_config2=ec2.describe_vpn_connections(VpnConnectionIds=[vpn2['VpnConnection']['VpnConnectionId']])
        vpn_config2=vpn_config2['VpnConnections'][0]['CustomerGatewayConfiguration']
        s3.put_object(
	    Body=str.encode(vpn_config2),
	    Bucket=bucket_name,
	    Key=bucket_prefix+'CSR2/'+region_id+'-'+vpn2['VpnConnection']['VpnConnectionId']+'.conf',
	    ACL='bucket-owner-full-control',
	    ServerSideEncryption='AES256'
	)
        log.info('Pushed VPN configurations to S3...')
        if config['SENDDATA'] == "Yes":
            regionDict = {}    
            postDict = {}
            regionDict['region'] = region_id    
            regionDict['vpn_connections'] = 2    
            postDict['Data'] = regionDict
            postDict['TimeStamp'] = str(datetime.datetime.now())
            postDict['Solution'] = 'SO0001'
            postDict['UUID'] = config['UUID']
            # API Gateway URL to make HTTP POST call
            url = 'https://5as186uhg7.execute-api.us-east-1.amazonaws.com/prod/generic'
            data=json.dumps(postDict)
            log.info(data)
            headers = {'content-type': 'application/json'}
            req = urllib2.Request(url, data, headers)
            rsp = urllib2.urlopen(req)
            rspcode = rsp.getcode()
            content = rsp.read()
            log.info("Response from APIGateway: %s, %s", rspcode, content)
	#Consider finishing after loading a new configuration to give config generator time to push the changes
	return