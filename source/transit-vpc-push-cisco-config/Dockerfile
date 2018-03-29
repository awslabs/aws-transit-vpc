# This Dockerfile encapsulates an Amazon Linux 1 environment similar to the
# runtime of Lambda to ensure all libraries will be compatible there. It's
# used to build the transit-vpc-push-cisco-config function (which requires
# external libraries)
FROM amazonlinux:1

# Update the Amazon Linux image and install packages we'll need
RUN yum update -y
RUN yum install -y libffi-devel python27-devel python27-virtualenv zip

# We'll copy our transit-vpc-push-cisco-config Lambda code over to the
# /app directory, with /app/venv serving as our virtualenv.
RUN mkdir /app
RUN virtualenv /app/venv
ENV VIRTUAL_ENV=/app/venv PATH=/app/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /app
COPY *.py ./transit-vpc-push-cisco-config/
RUN pip install transit-vpc-push-cisco-config/.
RUN zip -q -u -r -9 /transit-vpc-push-cisco-config.zip transit-vpc-push-cisco-config
WORKDIR /app/venv/lib/python2.7/site-packages
RUN zip -q -u -r -9 /transit-vpc-push-cisco-config.zip * -x 'pip*' 'easy*' 'setuptools*' 'wheel*'
WORKDIR /app/venv/lib64/python2.7/site-packages
RUN zip -q -u -r -9 /transit-vpc-push-cisco-config.zip * -x 'pip*' 'easy*' 'setuptools*' 'wheel*'
RUN cat /transit-vpc-push-cisco-config.zip

VOLUME /dist
