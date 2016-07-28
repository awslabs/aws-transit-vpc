# aws-transit-vpc
Source code for the AWS solution "Transit Network VPC (Cisco CSR). Please see the main solution page located at https://aws.amazon.com/answers/.

## Cloudformation templates

transit-vpc-primary-account.template
transit-vpc-second-account.template
transit-vpc-spoke-vpc.template
transit-vpc-spoke-vpc-withec2.template
transit-vpc-spoke-vpc-withec2-tsunamiudp.template

## Lambda source code

transit-vpc-poller.py
transit-vpc-push-cisco-config.py

***

Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.