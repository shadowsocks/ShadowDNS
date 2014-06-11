from setuptools import setup


with open('README.rst') as f:
    long_description = f.read()

setup(
    name="shadowdns",
    version="0.1.1",
    license='MIT',
    description="A DNS forwarder for shadowsock",
    author='clowwindy',
    author_email='clowwindy42@gmail.com',
    url='https://github.com/clowwindy/shadowdns',
    packages=['shadowdns'],
    package_data={
        'shadowdns': ['README.rst', 'LICENSE', 'config.json']
    },
    install_requires=[
        'shadowsocks==2.0.3'
    ],
    entry_points="""
    [console_scripts]
    ssdns = shadowdns.dnsrelay:main
    """,
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
