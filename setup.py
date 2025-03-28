from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="apikeyleak",
    version="0.1.0",
    author="mrprohack",
    author_email="your.email@example.com",
    description="A powerful and flexible tool for detecting potential API key leaks in your codebase",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/apikeyleektest",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "apikeyleek=apikeyleak.cli:main",
        ],
    },
) 