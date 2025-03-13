from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='crt_secret_sharing',
    version='0.1.0',
    description='Understanding CRT-based secret sharing',
    long_description=readme,
    author='Jakob Zornig Kjellberg',
    author_email='s224809@dtu.dk',
    url='https://github.com/JakobKjellberg02/CRT-based-Secret-Sharing-and-its-Applications',
    license=license,
    packages=find_packages(exclude=('tests', 'docs', 'assets', 'gui'))
)