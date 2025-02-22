"""
Project setup file.
"""

from setuptools import find_packages, setup

setup(
    name="SRAMsync",
    version="4.4.2",
    author="Gerben Venekamp",
    author_email="gerben.venekamp@surf.nl",
    description="Reading entries and attributes from SRAM LDAP and process them",
    url="https://github.com/SURFscz/SRAMsync/",
    install_requires=["Click", "pyldap", "jsonschema", "pyyaml", "click_logging", "typing-extensions"],
    entry_points={"console_scripts": ["sync-with-sram = SRAMsync.sync_with_sram:cli"]},
    python_requires=">=3.9",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3",
        "Operating System :: OS Independent",
    ],
)
