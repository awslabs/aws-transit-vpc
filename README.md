# AWS Transit VPC
A solution for creating a transit VPC with Cisco CSR instances. These templates rely on the following AWS Marketplace listings:
BYOL
https://aws.amazon.com/marketplace/pp/B00NF48FI2

License Included
https://aws.amazon.com/marketplace/pp/B00OCG4OAA

## OS/Python Environment Setup
```bash
sudo yum-config-manager --enable epel
sudo yum update -y
sudo pip install --upgrade pip
alias sudo='sudo env PATH=$PATH'
sudo pip install --upgrade setuptools
sudo pip install --upgrade virtualenv
```

## Building Lambda Package
```bash
cd deployment
./build-s3-dist.sh source-bucket-base-name
```
source-bucket-base-name should be the base name for the S3 bucket location where the template will source the Lambda code from.
The template will append '-[region_name]' to this value.
For example: ./build-s3-dist.sh solutions
The template will then expect the source code to be located in the solutions-[region_name] bucket

## CF template and Lambda function
Located in deployment/dist


***

Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
