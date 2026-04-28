from setuptools import setup, find_packages

setup(
    name="threatlens",
    version="1.0.0",
    description="Advanced Malicious APK & EXE Analyzer",
    author="ThreatLens Security Research",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "pefile>=2023.2.7",
        "androguard>=3.3.5",
    ],
    extras_require={
        "full": [
            "yara-python>=4.3.0",
            "requests>=2.31.0",
            "capstone>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threatlens=threatlens:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
