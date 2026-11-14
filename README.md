# Vulnerability Repair Pattern Mining

Python package interfaces for the repository's vulnerability-data preparation,
guidance-tree generation and retrieval, LLM-based repair, and patch evaluation.
The package currently wraps the existing implementations so their established
algorithms and result formats remain unchanged. Legacy scripts and import paths
remain available for existing workflows.

## Install

```bash
python -m pip install .
```

Install the optional development and CodeBLEU dependencies with
`python -m pip install '.[dev,codebleu]'`. The package requires Python 3.10+.

## Python API

```python
from vulnrepair.data import PrimeVulLoader
from vulnrepair.data.split import split_dataset

dataset = PrimeVulLoader().load("data/primevul.jsonl")
train_test = split_dataset(dataset.to_frame(), cwe_column="cwe")
```

Data loaders accept the same input formats and column options as the existing
data normalizer. `CVEFixesLoader`, `BigVulLoader`, `PrimeVulLoader`, and
`TitanVulLoader` are named entry points for caller-supplied dataset files; they
do not download data or assume dataset-specific schemas.

The other package interfaces are organized under `vulnrepair.guidance`,
`vulnrepair.retrieval`, `vulnrepair.repair`, and `vulnrepair.evaluation`. For
example, `Repairer` accepts an `LLMClient` and a `RepairRequest`; API keys and
Ollama connection settings continue to use the existing environment variables.

Summary generation is available separately under `vulnrepair.summary`; it is
not invoked automatically by guidance-tree generation. Pass a patch and its
metadata in a `SummaryGenerationRequest`. The generator returns one result per
requested variant, including the generated text, prompt, and token counts when
the provider supplies them:

```python
from vulnrepair.summary import SummaryGenerationRequest, SummaryGenerator

generator = SummaryGenerator(provider="openai", model="gpt-5.1")
summaries = generator.generate(
    SummaryGenerationRequest(
        patch="The patch text...",
        cwe_id="CWE-79",
        commit_message="Validate user input before rendering",
        num_variants=3,
        prompt_mode="semantic",
    )
)
for result in summaries:
    print(result.summary)
```

Supported providers are `openai` and `ollama`; prompt modes are `orig`,
`hybrid`, and `semantic`. The provider's API key or connection settings use the
existing environment variables. Call this API explicitly before tree building
when summaries are needed.

To generate a guidance tree, pass `GuidanceGenerator.generate` a
`GuidanceGenerationRequest`. Its `patches` must be a pandas DataFrame with a
`patch_id` column; `summary` and `patch` columns are also used when present.
`prepare_patches_from_summary_files` converts the existing summary-record format
to this DataFrame shape. `TreeConfig` is available from the public guidance API.
Its fields and defaults are `min_group_size=1`, `max_group_size=6`,
`min_nodes_to_continue=1`, `max_depth=10`, `force_merge_threshold=2`,
`temperature=0.0`, `model="gpt-5"`, `provider="openai"`,
`tree_type="combined"`, and `max_tokens=100000`.

```python
import pandas as pd
from mining.trees.utils.build_tree import prepare_patches_from_summary_files
from vulnrepair.guidance import (
    GuidanceGenerationRequest,
    GuidanceGenerator,
    TreeConfig,
)

summary_records = pd.read_json("data/summaries.jsonl", lines=True)
patches = prepare_patches_from_summary_files(summary_records)

root, nodes, depth = GuidanceGenerator().generate(
    GuidanceGenerationRequest(
        patches=patches,
        config=TreeConfig(
            max_depth=8,
            provider="openai",
            model="gpt-5",
            tree_type="combined",
        ),
        cwe_id="CWE-79",
    )
)
```

The guidance-tree builder retains its existing tree-building behavior and
`(root, nodes, depth)` return format.

## Command line

The `vulnrepair-data`, `vulnrepair-guidance`, and `vulnrepair-repair` commands
expose the existing script arguments. `vulnrepair-evaluate --input RESULTS.csv`
calculates the existing metrics from a results file and can write the overall
summary with `--output SUMMARY.json`. The original script/module entry points
remain supported. Experiment data and generated artifacts are intentionally
not included in the Python package.

Clustering code is not part of the new package surface.
