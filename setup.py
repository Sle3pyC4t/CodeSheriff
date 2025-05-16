from setuptools import setup, find_packages

setup(
    name="CodeSheriff",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "tqdm>=4.66.1",
    ],
    entry_points={
        "console_scripts": [
            "code-sheriff=CodeSheriff.cli:main",
        ],
    },
    python_requires=">=3.7",
) 