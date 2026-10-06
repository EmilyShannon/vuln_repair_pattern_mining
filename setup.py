from pathlib import Path

from setuptools import find_namespace_packages, find_packages, setup

ROOT = Path(__file__).parent
legacy_packages = find_namespace_packages(
    where=str(ROOT),
    include=[
        "data",
        "data.analysis",
        "data.utils",
        "eval",
        "retrieval",
        "mining",
        "mining.trees",
        "mining.trees.utils",
    ],
)
source_packages = find_packages(
    where=str(ROOT / "src"),
    include=["vulnrepair", "vulnrepair.*"],
)

setup(
    name="vuln-repair-pattern-mining",
    version="0.1.0",
    description=(
        "Tools for vulnerability datasets, repair guidance, retrieval, repair, "
        "and evaluation."
    ),
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    packages=source_packages + legacy_packages,
    package_dir={
        "": "src",
        "data": "data",
        "eval": "eval",
        "retrieval": "retrieval",
        "mining": "mining",
    },
    include_package_data=True,
    package_data={
        "eval": ["llm_based_repair_prompt_templates.json"],
        "data.analysis": ["allowed_mappable_cwes.txt"],
    },
    install_requires=[
        "matplotlib>=3.7",
        "nltk>=3.8",
        "numpy>=1.24",
        "ollama>=0.3",
        "openai>=1.30",
        "pandas>=2.0",
        "python-dotenv>=1.0",
    ],
    extras_require={
        "codebleu": ["codebleu"],
        "dev": ["pytest>=8"],
    },
    entry_points={
        "console_scripts": [
            "vulnrepair-data=vulnrepair.cli.data:main",
            "vulnrepair-guidance=vulnrepair.cli.guidance:main",
            "vulnrepair-repair=vulnrepair.cli.repair:main",
            "vulnrepair-evaluate=vulnrepair.cli.evaluate:main",
        ]
    },
)
