from setuptools import setup

setup(
    name="cua-sync",
    version="1.0",
    py_module=["cua_sync"],
    install_requires=[
        "Click",
        "future-fstrings"
        ],
    entry_points={
        'console_scripts': [
            "cua-sync = cua_sync:cli"
        ]
    }
)
