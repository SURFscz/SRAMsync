from setuptools import setup

setup(
    name="sync-with-sram",
    version="1.0",
    py_module=["sync_with_sram"],
    install_requires=["Click", "future-fstrings"],
    entry_points={"console_scripts": ["sync-with-sram = sync_with_sram:cli"]},
)
