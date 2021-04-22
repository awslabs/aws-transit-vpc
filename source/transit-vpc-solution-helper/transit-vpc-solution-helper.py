######################################################################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.                                           #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

from pycfn_custom_resource.lambda_backed import CustomResource
import boto3
from botocore.client import Config
from zipfile import ZipFile
import urllib
import os
import string
import shutil
import ast
import paramiko
import crypt
import binascii
import logging
import uuid
import json
import datetime
import re

log = logging.getLogger()
log.setLevel(logging.INFO)
USER_AGENT_STRING = os.environ['USER_AGENT_STRING']

# Function to create an S3 bucket event to invoke the new Lambda Function
def createS3Event(FunctName, S3Event, AccountId):
    try:
        funct = boto3.client('lambda', config=Config(user_agent_extra=USER_AGENT_STRING))
        try:
            response = funct.remove_permission(FunctionName=FunctName, StatementId='S3Events_' + FunctName)
        except Exception as e:
            log.info("Permission doesn't exist")

        response = funct.add_permission(
            FunctionName=FunctName,
            StatementId='S3Events_' + FunctName,
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn="arn:aws:s3:::" + S3Event['Bucket'],
            SourceAccount=AccountId

        )
        s3 = boto3.client('s3', config=Config(signature_version='s3v4', user_agent_extra=USER_AGENT_STRING))
        response = s3.put_bucket_notification_configuration(
            Bucket=S3Event['Bucket'],
            NotificationConfiguration=S3Event['EventPattern']
        )
        log.info("Add permission: %s", response)
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def StoreInS3(S3Info):
    try:
        log.debug("Storing all this data in S3: %s.", S3Info)
        for S3Object in S3Info:
            # log.error("Storing requested data in S3: %s.", S3Object)
            s3 = boto3.client('s3', config=Config(signature_version='s3v4', user_agent_extra=USER_AGENT_STRING))
            response = s3.put_object(
                Bucket=S3Object['Bucket'],
                Key=S3Object['Key'],
                Body=S3Object['Body'],
                ACL='bucket-owner-full-control',
                ServerSideEncryption='AES256'
            )
            log.info("Data saved to %s/%s", S3Object['Bucket'], S3Object['Key'])
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def StoreInS3KMS(S3Info):
    try:
        log.debug("Storing all this data in S3: %s.", S3Info)
        for S3Object in S3Info:
            # log.debug("Storing requested data in S3: %s.", S3Object)
            s3 = boto3.client('s3', config=Config(signature_version='s3v4', user_agent_extra=USER_AGENT_STRING))
            response = s3.put_object(
                Bucket=S3Object['Bucket'],
                Key=S3Object['Key'],
                Body=S3Object['Body'],
                ACL='bucket-owner-full-control',
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=S3Object['SSEKMSKeyId']
            )
            log.info("Data saved to %s/%s", S3Object['Bucket'], S3Object['Key'])
    except Exception as e:
        log.error("Exception is: %s", e)
        raise e


def SendAnonymousData(AnonymousData):
    log.info("Sending anonymous data")
    TimeNow = datetime.datetime.utcnow().isoformat()
    TimeStamp = str(TimeNow)
    AnonymousData['TimeStamp'] = TimeStamp
    data = json.dumps(AnonymousData)
    log.info("Data: %s", data)
    data_utf8 = data.encode('utf-8')
    url = 'https://metrics.awssolutionsbuilder.com/generic'
    headers = {
        'content-type': 'application/json; charset=utf-8',
        'content-length': len(data_utf8)
    }
    req = urllib.request.Request(url, data_utf8, headers)
    rsp = urllib.request.urlopen(req)
    rspcode = rsp.getcode()
    content = rsp.read()
    log.info("Response from APIGateway: %s, %s", rspcode, content)
    return data


def createRSAkey(bits=1024):
    tmpdir = '/tmp/keys/'
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)
    os.makedirs(tmpdir)
    k = paramiko.RSAKey.generate(bits)
    k.write_private_key_file(tmpdir + 'key')
    pkeyfile = open(tmpdir + 'key', "r")
    pkey = pkeyfile.read()
    pkeyfile.close()
    os.remove(tmpdir + 'key')
    return pkey, k.get_base64(), k.get_fingerprint()


def createRandomPassword(pwdLength=13, specialChars="True"):
    log.info("Creating random password")
    if specialChars is None:
        specialChars = "True"
    # Generate new random password
    chars = string.ascii_letters + string.digits
    if specialChars == "True":
        chars += '#$%^&+='
        p=re.compile('^(?=.{1,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[#$%^&+=]).*$')
    else:
        p=re.compile('^(?=.{1,})(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$')
    numTries = 0
    pwdFound = False
    while not pwdFound:
        password = ''
        numTries += 1
        for i in range(int(pwdLength)):
            password += chars[ord(os.urandom(1)) % len(chars)]
        m=p.match(password)
        if m is not None:
            pwdFound = True
    log.info("Password created after %s tries", numTries)
    log.debug("%s", password)
    return password


def createUniqueID():
    log.info("Creating Unique ID")
    # Generate new random Unique ID
    uniqueID = uuid.uuid4()
    log.debug("UUID: %s", uniqueID)
    return uniqueID


def md5hash(value, salt):
    return crypt.crypt(value, '$1$' + salt)


class myCustomResource(CustomResource):
    def __init__(self, event):
        super(myCustomResource, self).__init__(event)

    def create(self):
        try:
            FunctName = self._resourceproperties.get('FunctionName')
            FunctArn = self._resourceproperties.get('LambdaArn')
            S3Event = self._resourceproperties.get('S3Event')
            S3StoreKMS = self._resourceproperties.get('StoreInS3KMS')
            CreateSshKey = self._resourceproperties.get('CreateSshKey')
            CreateRandomPassword = self._resourceproperties.get('CreateRandomPassword')
            CreateUniqueID = self._resourceproperties.get('CreateUniqueID')
            SendData = self._resourceproperties.get('SendAnonymousData')
            AccountId = self._resourceproperties.get('AccountId')
            response = None

            if S3Event is not None:
                log.debug("Create S3Event: %s", S3Event)
                S3Event = ast.literal_eval(S3Event)
                if FunctArn is not None:
                    S3Event['EventPattern']['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'] = FunctArn
                createS3Event(FunctName, S3Event, AccountId)

            if S3StoreKMS is not None:
                log.debug("Create S3StoreKMS: %s", S3StoreKMS)
                S3StoreKMS = ast.literal_eval(S3StoreKMS)
                StoreInS3KMS(S3StoreKMS)

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Created'})
                data = SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(data)}
                log.debug("%s", response)

            if CreateSshKey is not None:
                log.debug("Create SshKey: %s", CreateSshKey)
                prikey, pubkey, fingerprint = createRSAkey()
                CreateSshKey = ast.literal_eval(CreateSshKey)
                # Need logic for if using SSE-KMS
                if CreateSshKey.get('SSEKMSKeyId', '') != '':
                    StoreInS3KMS([{"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PrivateKey'],
                                   "SSEKMSKeyId": CreateSshKey['SSEKMSKeyId'], "Body": prikey},
                                  {"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PublicKey'],
                                   "SSEKMSKeyId": CreateSshKey['SSEKMSKeyId'], "Body": pubkey}])
                else:
                    StoreInS3([{"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PrivateKey'],
                                "Body": prikey},
                               {"Bucket": CreateSshKey['Bucket'], "Key": CreateSshKey['PublicKey'], "Body": pubkey}])
                response = {"Status": "SUCCESS", "MD5": md5hash(prikey, prikey[51:55]), "PubKey": pubkey,
                            "Fingerprint": str(binascii.hexlify(fingerprint), "ascii")}

            if CreateRandomPassword is not None:
                # Expect value of CreateRandomPassword to be the desired password length
                password = createRandomPassword(CreateRandomPassword, self._resourceproperties.get('RandomPasswordSpecialCharacters'))
                response = {"Status": "SUCCESS", "Password": password}

            if CreateUniqueID is not None:
                # Value of CreateUniqueID does not matter
                newID = createUniqueID()
                response = {"Status": "SUCCESS", "UUID": str(newID)}
                log.debug("%s", response)

            if response is None:
                response = {"Status": "SUCCESS"}

            # Results dict referenced by GetAtt in template
            return response

        except Exception as e:
            log.error("Create exception: %s", e)
            return {"Status": "FAILED", "Reason": str(e)}

    def update(self):
        try:
            FunctName = self._resourceproperties.get('FunctionName')
            FunctArn = self._resourceproperties.get('LambdaArn')
            S3Event = self._resourceproperties.get('S3Event')
            SendData = self._resourceproperties.get('SendAnonymousData')
            AccountId = self._resourceproperties.get('AccountId')

            response = None

            if S3Event is not None:
                S3Event = ast.literal_eval(S3Event)
                S3Event['EventPattern']['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'] = FunctArn
                createS3Event(FunctName, S3Event, AccountId)

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Updated'})
                SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(SendData)}
                log.debug("%s", response)

            if response is None:
                response = {"Status": "SUCCESS"}

            # Results dict referenced by GetAtt in template
            return response

        except Exception as e:
            log.error("Update exception: %s", e)
            return {"Status": "FAILED", "Reason": str(e)}

    # Needs a lot of work to make sure this properly cleans up CWE, S3Events, or stored S3 data!!!
    def delete(self):
        try:
            FunctName = self._resourceproperties.get('FunctionName')
            CreateSshKey = self._resourceproperties.get('CreateSshKey')
            SendData = self._resourceproperties.get('SendAnonymousData')

            log.info("Delete called, cleaning up")

            if SendData is not None:
                log.debug("Sending Data: %s", SendData)
                SendData = ast.literal_eval(SendData)
                SendData['Data'].update({'CFTemplate': 'Deleted'})
                data = SendAnonymousData(SendData)
                response = {"Status": "SUCCESS", "Data": str(data)}
                log.debug("%s", response)

            if CreateSshKey is not None:
                CreateSshKey = ast.literal_eval(CreateSshKey)
                s3 = boto3.client('s3', config=Config(signature_version='s3v4', user_agent_extra=USER_AGENT_STRING))
                s3.delete_object({'Bucket': CreateSshKey['Bucket'], 'Key': CreateSshKey['PrivateKey']})
                s3.delete_object({'Bucket': CreateSshKey['Bucket'], 'Key': CreateSshKey['PublicKey']})

            return {"Status": "SUCCESS"}

        # Delete operations do not return result data
        except Exception as e:
            log.error("Delete exception: %s -- %s", FunctName, e)
            return {"Status": "FAILED", "Reason": str(e)}


def lambda_handler(event, context):
    #print "Lambda Event \n", event
    #print "Lambda Context \n", context

    resource = myCustomResource(event)
    resource.process_event()
    return {'message': 'done'}
