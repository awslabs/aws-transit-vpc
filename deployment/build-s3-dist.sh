#!/bin/bash
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name trademarked-solution-name version-code
#
# Paramenters:
#  - template-bucket: Name for the S3 bucket location where the templates are found
#  - source-bucket-base-name: Name for the S3 bucket location where the Lambda source
#    code is deployed. The template will append '-[region_name]' to this bucket name.
#  - trademarked-solution-name: name of the solution for consistency
#  - version-code: version of the package
#
#    For example: ./build-s3-dist.sh template-bucket source-bucket-base-name my-solution v3.0
#    The template will then expect the source code to be located in the solutions-[region_name] bucket
#
# Check to see if input has been provided:
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
    echo "Please provide the base template-bucket, source-bucket-base-name, trademark-approved-solution-name and version"
    echo "For example: ./build-s3-dist.sh solutions solutions-code trademarked-solution-name v3.0"
    exit 1
fi

echo "template bucket = $1"
echo "source bucket = $2"
echo "solution = $3"
echo "version = $4"

# Get reference for all important folders
template_dir="$PWD"
source_dir="$template_dir/../source"

# There are now TWO dist directories
template_dist_dir="$template_dir/global-s3-assets"
build_dist_dir="$template_dir/regional-s3-assets"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist folders"
echo "------------------------------------------------------------------------------"

echo "rm -rf $template_dist_dir"
rm -rf $template_dist_dir
echo "mkdir -p $template_dist_dir"
mkdir -p $template_dist_dir

echo "rm -rf $build_dist_dir"
rm -rf $build_dist_dir
echo "mkdir -p $build_dist_dir"
mkdir -p $build_dist_dir

echo "find $source_dir -iname \"dist\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "dist" -type d -exec rm -r "{}" \; 2> /dev/null
echo "find ../ -type f -name 'package-lock.json' -delete"
find "$source_dir" -type f -name 'package-lock.json' -delete
echo "find ../ -type f -name '.DS_Store' -delete"
find "$source_dir" -type f -name '.DS_Store' -delete
echo "find $source_dir -iname \"package\" -type d -exec rm -r \"{}\" \; 2> /dev/null"
find "$source_dir" -iname "package" -type d -exec rm -r "{}" \; 2> /dev/null

echo "------------------------------------------------------------------------------"
echo "[Packing] Templates"
echo "------------------------------------------------------------------------------"

SUB1="s/%TEMPLATE_OUTPUT_BUCKET%/$1/g"
SUB2="s/%DIST_OUTPUT_BUCKET%/$2/g"
SUB3="s/%SOLUTION_NAME%/$3/g"
SUB4="s/%VERSION%/$4/g"

for FULLNAME in ./*.template
do
  TEMPLATE=`basename $FULLNAME`
  echo "Preparing $TEMPLATE"
  sed -e $SUB1 -e $SUB2 -e $SUB3 -e $SUB4 $template_dir/$TEMPLATE > $template_dist_dir/$TEMPLATE
done


echo "------------------------------------------------------------------------------"
echo "[Packing] Transit VPC Poller"
echo "------------------------------------------------------------------------------"
pwd
cd "$source_dir"/transit-vpc-poller || exit 1
zip -q -r9 "$build_dist_dir"/transit-vpc-poller.zip .


echo "------------------------------------------------------------------------------"
echo "[Packing] Transit VPC Push Cisco Config"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/transit-vpc-push-cisco-config || exit 1
pip3 install . --target ./package
cd "$source_dir"/transit-vpc-push-cisco-config/package || exit 1
zip -q -r9 "$build_dist_dir"/transit-vpc-push-cisco-config.zip .
cd "$source_dir"/transit-vpc-push-cisco-config || exit 1


echo "------------------------------------------------------------------------------"
echo "[Packing] Transit VPC Solution Helper"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/transit-vpc-solution-helper || exit 1

pip3 install . --target ./package
cd "$source_dir"/transit-vpc-solution-helper/package || exit 1
zip -q -r9 "$build_dist_dir"/transit-vpc-solution-helper.zip .
cd "$source_dir"/transit-vpc-solution-helper || exit 1

