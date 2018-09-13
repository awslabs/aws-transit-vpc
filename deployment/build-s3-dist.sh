#!/bin/bash

# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#sudo apt-get update
#sudo apt-get install zip -y
#sudo pip install --upgrade pip
#pip install --upgrade setuptools
#pip install --upgrade virtualenv

# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name
# source-bucket-base-name should be the base name for the S3 bucket location where the template will source the Lambda code from.
# The template will append '-[region_name]' to this bucket name.
# For example: ./build-s3-dist.sh solutions
# The template will then expect the source code to be located in the solutions-[region_name] bucket

# Check to see if input has been provided:
if [ -z "$1" ]; then
    echo "Please provide the base source bucket name where the lambda code will eventually reside.\nFor example: ./build-s3-dist.sh solutions"
    exit 1
fi

# Build source
echo "Staring to build distribution"
echo "export deployment_dir=`pwd`"
export deployment_dir=`pwd`
echo "mkdir -p dist"
mkdir -p dist
echo "cp -f *.template dist"
cp -f *.template dist
echo "Updating code source bucket in templates with $1"
export replace="s/%%BUCKET_NAME%%/$1/g"
echo "sed -i -e $replace dist/transit-vpc-primary-account-existing-vpc.template"
sed -i -e $replace dist/transit-vpc-primary-account-existing-vpc.template
echo "sed -i -e $replace dist/transit-vpc-primary-account-marketplace.template"
sed -i -e $replace dist/transit-vpc-primary-account-marketplace.template
echo "sed -i -e $replace dist/transit-vpc-primary-account.template"
sed -i -e $replace dist/transit-vpc-primary-account.template
echo "sed -i -e $replace dist/transit-vpc-second-account.template"
sed -i -e $replace dist/transit-vpc-second-account.template

cd $deployment_dir/../source/transit-vpc-poller
echo "Creating transit-vpc-poller ZIP file"
zip -q -r9 $deployment_dir/dist/transit-vpc-poller.zip *
echo "Building transit-vpc-push-cisco-config ZIP file"
cd $deployment_dir/dist
pwd
echo "virtualenv env"
virtualenv env
echo "source env/bin/activate"
source env/bin/activate
echo "pip install $deployment_dir/../source/transit-vpc-push-cisco-config/. --target=$deployment_dir/dist/env/lib/python2.7/site-packages/"
pip install $deployment_dir/../source/transit-vpc-push-cisco-config/. --target=$deployment_dir/dist/env/lib/python2.7/site-packages/
# TransitVPC-11 - 09/06/2018 - Allow build fail
# fail build if pip install fails
instl_status=$?
if [ ${instl_status} != '0' ]; then
  echo "pip install cisco configurator status: ${instl_status}"
  exit ${instl_status}
fi
cd $deployment_dir/dist/env/lib/python2.7/site-packages/
zip -r9 $deployment_dir/dist/transit-vpc-push-cisco-config.zip .
cd $deployment_dir/dist
zip -q -d transit-vpc-push-cisco-config.zip pip*
zip -q -d transit-vpc-push-cisco-config.zip easy*
echo "Clean up build material in $VIRTUAL_ENV"
rm -rf $VIRTUAL_ENV
echo "Completed building distribution"
