#!/bin/bash -ex
# ./build-s3-dist.sh <s3-bucket-name>
#
# You must have Docker installed (to ensure we get a clean copy of Amazon Linux)

# Check to see if input has been provided
if [[ $# -ne 1 || "$1" = "-h" || "$1" = "--help" ]]; then
  echo "Usage: build-s3-dist.sh <bucket-name>" 1>&2
  echo "<bucket-name> is the name of the S3 bucket that will house the Lambda" 1>&2;
  echo "code." 1>&2;
  exit 1;
fi

s3_bucket="$1"
deployment_dir="$(dirname "$0")"
base_dir="$(cd $deployment_dir/..; /bin/pwd)"
source_dir="$base_dir/source"
dist_dir="$base_dir/dist"

# Create the dist directory if it doesn't exist.
test -d "$dist_dir" || mkdir -p "$dist_dir"

# Replace the %%BUCKET_NAME%% placeholder
echo "Updating S3 bucket name in templates with $s3_bucket"
replace="s/%%BUCKET_NAME%%/$s3_bucket/g"
for sourcepath in "$deployment_dir"/*.template; do
  filename="$(basename "$sourcepath")"
  destpath="$dist_dir/$filename"
  sed -e $replace "$sourcepath" > "$destpath";
done;

# Create the Lambda ZIP archive for the transit poller. This is just the single
# transit-vpc-poller.py file.
echo "Creating transit-vpc-poller ZIP file"
cd "$source_dir/transit-vpc-poller"
zip -q -r9 "$dist_dir/transit-vpc-poller.zip" *

# Create the Lambda ZIP archive for the CSR configuration pusher. This is more
# involved since it involves external libraries
echo "Creating transit-vpc-push-cisco-config ZIP file"
cd "$source_dir/transit-vpc-push-cisco-config"
docker build -t transit-vpc-push-cisco-config:latest .
docker run --mount "type=bind,dst=/dist,src=$dist_dir" transit-vpc-push-cisco-config:latest \
  cp /transit-vpc-push-cisco-config.zip /dist

echo "Distribution files: $dist_dir"
