#!/usr/bin/env python3
"""
FastPort - High-Performance Async Port Scanner with CVE Integration

A modern, blazing-fast port scanner that rivals NMAP in performance while providing
enhanced features like automatic CVE detection and interactive TUI dashboards.
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return __doc__

setup(
    name='fastport',
    version='1.0.0',
    description='High-performance async port scanner with CVE integration',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='HDAIS Project',
    author_email='',
    url='https://github.com/yourusername/fastport',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
    ],
    keywords='port scanner security nmap async asyncio cve vulnerability network',
    python_requires='>=3.8',

    install_requires=[
        'aiohttp>=3.8.0',
        'requests>=2.28.0',
        'rich>=13.0.0',  # For beautiful TUI
    ],

    extras_require={
        'gui': [
            'PyQt6>=6.0.0',  # For GUI interface
        ],
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'black>=22.0.0',
            'flake8>=5.0.0',
            'mypy>=0.990',
            'maturin>=1.0.0',  # For building Rust core
        ],
        'rust': [
            # Rust core is built separately via maturin
            # See BUILD.md for instructions
        ],
    },

    entry_points={
        'console_scripts': [
            'fastport=fastport.scanner:main',
            'fastport-tui=fastport.scanner_tui:main',
            'fastport-pro=fastport.scanner_pro_tui:main',
            'fastport-gui=fastport.scanner_gui:main',
            'fastport-cve=fastport.cve_scanner:main',
            'fastport-cve-tui=fastport.cve_scanner_tui:main',
            'fastport-lookup=fastport.cve_lookup:main',
        ],
    },

    project_urls={
        'Bug Reports': 'https://github.com/yourusername/fastport/issues',
        'Source': 'https://github.com/yourusername/fastport',
        'Documentation': 'https://github.com/yourusername/fastport/blob/main/README.md',
    },

    include_package_data=True,
    zip_safe=False,
)
