#!/usr/bin/env python3
"""
Setup script for Advanced Cross-Platform WiFi Cracking Suite
"""

from setuptools import setup, find_packages
import os

def read_readme():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()

def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="wifi-cracking-suite",
    version="1.0.0",
    author="Ali Zafar",
    author_email="",
    description="Advanced Cross-Platform WiFi Cracking Suite",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/AliZafar/wifi-cracking-suite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    keywords="wifi wireless security cracking penetration-testing network-scanner",
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wifi-cracker=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/AliZafar/wifi-cracking-suite/issues",
        "Source": "https://github.com/AliZafar/wifi-cracking-suite",
    },
)
