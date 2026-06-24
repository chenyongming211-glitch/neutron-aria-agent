from setuptools import find_packages
from setuptools import setup


setup(
    name="neutron-aria",
    version="0.1.0",
    description="OpenStack Neutron adapter for Aria datapath",
    packages=find_packages(exclude=["neutron_aria.tests", "neutron_aria.tests.*"]),
    entry_points={
        "console_scripts": [
            "neutron-aria-agent=neutron_aria.agent.main:main",
        ],
    },
)
