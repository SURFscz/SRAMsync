"""
Project setup file.
"""

from setuptools import setup, find_packages

setup(
    name="SRAMsync",
    version="3.0.0",
    author="Gerben Venekamp",
    author_email="gerben.venekamp@surf.nl",
    description="Reading entries and attributes from SRAM LDAP and process them",
    url="https://github.com/venekamp/CUA-sync",
    install_requires=["Click", "pyldap", "jsonschema", "pyyaml", "click_logging"],
    entry_points={"console_scripts": ["sync-with-sram = SRAMsync.sync_with_sram:cli"]},
    python_requires=">=3.6",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3",
        "Operating System :: OS Independent",
    ],
)
