from setuptools import find_packages
from setuptools import setup


setup(
    name="neutronclient-aria",
    version="0.1.0",
    description="Legacy python-neutronclient commands for Aria ACL",
    packages=find_packages(exclude=["neutronclient_aria.tests", "neutronclient_aria.tests.*"]),
    entry_points={
        "neutronclient.extension": [
            "aria_acl=neutronclient_aria.v2_0.aria_acl",
        ],
    },
)
