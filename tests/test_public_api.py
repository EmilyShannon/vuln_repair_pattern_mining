import pandas as pd

from vulnrepair.data import CVEFixesLoader, VulnerabilityExample
from vulnrepair.data.filtering import filter_by_cwe
from vulnrepair.data.models import VulnerabilityDataset
from vulnrepair.data.split import split_dataset
from vulnrepair.evaluation import Evaluator, PatchComparator, RepairEvaluation
from vulnrepair.repair import LLMClient, RepairRequest, Repairer


def test_dataset_loader_normalizes_and_preserves_metadata(tmp_path):
    source = tmp_path / "cvefixes.csv"
    pd.DataFrame(
        {
            "cve_id": ["CVE-2024-1234"],
            "cwe_id": ["CWE-79"],
            "vul_func": ["return input;"],
            "fixed_func": ["return escape(input);"],
            "project": ["example"],
        }
    ).to_csv(source, index=False)

    dataset = CVEFixesLoader().load(source)

    assert dataset.name == "cvefixes"
    assert dataset.examples[0].cve_id == "CVE-2024-1234"
    assert dataset.examples[0].cwe_id == "CWE-79"
    assert dataset.to_frame().loc[0, "project"] == "example"


def test_cwe_filter_and_split_keep_rows():
    dataset = VulnerabilityDataset(
        name="sample",
        examples=[
            VulnerabilityExample(cwe_id="CWE-79", patch="a"),
            VulnerabilityExample(cwe_id="CWE-79", patch="b"),
            VulnerabilityExample(cwe_id="CWE-125", patch="c"),
        ],
    )
    frame = dataset.to_frame()

    filtered = filter_by_cwe(frame, ["cwe-79"])
    split = split_dataset(filtered, cwe_column="cwe", random_state=7)

    assert len(split.train) + len(split.test) == 2
    assert set(split.train["patch"]) | set(split.test["patch"]) == {"a", "b"}


def test_repairer_uses_existing_prompt_and_response_helpers():
    class DummyResponse:
        output_text = "<repaired_code>safe()</repaired_code>"

    class DummyClient:
        responses = None

        def __init__(self):
            self.responses = self

        def create(self, **kwargs):
            return DummyResponse()

    repairer = Repairer(LLMClient("openai", "test-model", client=DummyClient()))

    result = repairer.repair(RepairRequest("unsafe()", prompt_template="zero_shot"))

    assert result.repaired_code == "safe()"
    assert "unsafe()" in result.prompt


def test_evaluation_adapters_return_existing_metrics():
    comparison = PatchComparator().compare(
        RepairEvaluation(reference_patch="fixed()", candidate_patch="fixed()")
    )
    evaluated = Evaluator().evaluate(
        pd.DataFrame(
            [
                {
                    "prompt_template": "zero_shot",
                    "guidance_used": False,
                    "ground_truth_patch": "fixed()",
                    "extracted_patch": "fixed()",
                }
            ]
        )
    )

    assert comparison["patch_match"] is True
    assert evaluated.overall["num_samples"] == 1
