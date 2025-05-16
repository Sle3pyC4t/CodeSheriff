from setuptools import setup, find_packages

setup(
    name="CodeSheriff",
    version="0.1.0",
    py_modules=["cli"],
    packages=["core", "integrations", "utils"],
    install_requires=[
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "tqdm>=4.66.1",
    ],
    entry_points={
        "console_scripts": [
            "code-sheriff=cli:main",
        ],
    },
    python_requires=">=3.7",
) 