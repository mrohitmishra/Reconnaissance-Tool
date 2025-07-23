#!/usr/bin/env python3
"""
Setup script for Bug Bounty Reconnaissance Tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="bug-bounty-recon-tool",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive reconnaissance tool for authorized security testing and bug bounty research",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bug-bounty-recon-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "recon-tool=recon_tool:main",
        ],
    },
    keywords="security, reconnaissance, bug-bounty, penetration-testing, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/bug-bounty-recon-tool/issues",
        "Source": "https://github.com/yourusername/bug-bounty-recon-tool",
        "Documentation": "https://github.com/yourusername/bug-bounty-recon-tool/wiki",
    },
)
