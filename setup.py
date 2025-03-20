from setuptools import setup, find_packages

# Read dependencies from requirements.txt
with open("requirements.txt") as f:
    requirements = f.read().strip().splitlines()

setup(
    name="RepoGraph",
    version="0.1.0",
    description="A package for analyzing and visualizing repository dependency graphs.",
    author="AIBACRP",
    author_email="your.email@example.com",
    url="https://github.com/AI-Based-Automated-Code-Review-Platform/RepoGraph",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    package_data={
        "repograph": ["*.py", "build/my-languages.so"],
    }
)