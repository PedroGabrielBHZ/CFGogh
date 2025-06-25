from setuptools import setup, find_packages

setup(
    name="cfgogh",
    version="0.1.0",
    author="Pedro Gabriel Amorim Soares",
    author_email="pedrogabrielbhz@gmail.com",
    description="A CLI tool to analyze smart contracts using Slither and visualize tainted flows in CFG.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=["slither-analyzer", "graphviz", "matplotlib", "click"],
    entry_points={
        "console_scripts": [
            "slither-cfg-analyzer=main:main",
        ],
    },
)
