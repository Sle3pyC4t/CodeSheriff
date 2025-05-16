from setuptools import setup, find_packages

setup(
    name='neov',
    version='0.1.0',
    author='matvey',
    author_email='cbisk@gmail.com',
    description='telegram',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/ваш_username/qtpv',
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[
        'requests',
    ],
)
