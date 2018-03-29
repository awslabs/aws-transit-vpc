# coding: utf-8

from setuptools import setup

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
        'Programming Language :: Python :: 2.7',
    ],
)
