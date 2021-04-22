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
# coding: utf-8


from setuptools import setup, find_packages
# TransitVPC-11 - 09/06/2018 - Pip version
# pip version handling
try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements

setup(
    name='transit_vpc_push_cisco_config',
    version='2.0',
    description='AWS Transit VPC Push Cisco Config',
    author='AWS Solutions Builder',
    license='ASL',
    zip_safe=False,
    packages=['transit_vpc_push_cisco_config'],
    package_dir={'transit_vpc_push_cisco_config': '.'},
    install_requires=[
        'paramiko>=1.16.0',
        'transit_vpc_push_cisco_config>=2.0'
    ],
    classifiers=[
        'Programming Language :: Python :: 3.7',
    ],
)