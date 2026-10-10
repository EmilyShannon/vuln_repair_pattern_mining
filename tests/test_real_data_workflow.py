"""Bounded integration test for the public API against available local real data."""

import json
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import pytest

from vulnrepair.data import PrimeVulLoader
from vulnrepair.evaluation import Evaluator
from vulnrepair.guidance import GuidanceGenerationRequest
from vulnrepair.guidance.generation import GuidanceGenerator
from vulnrepair.repair import LLMClient, RepairRequest, Repairer


ROOT = Path(__file__).resolve().parents[1]
RAW_DATA = ROOT / "data" / "raw" / "primevul_train.jsonl"
SUMMARIES = ROOT / "mining" / "summaries"
ARTIFACTS = ROOT / "tests" / "artifacts" / "real_data_workflow"
TARGET_CWE = "CWE-310"
MAX_RAW_RECORDS_TO_SCAN = 1_000
SUMMARY_RECORD_LIMIT = 2


def _read_real_primevul_record():
    with RAW_DATA.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index >= MAX_RAW_RECORDS_TO_SCAN:
                break
            record = json.loads(line)
            if (
                str(record.get("target")) == "1"
                and TARGET_CWE in str(record.get("cwe", ""))
                and str(record.get("func", "")).strip()
            ):
                return record
    pytest.skip(f"No positive {TARGET_CWE} sample found in the scanned PrimeVul records")


def _read_real_summaries(vulnerable_code):
    code_anchors = [
        line.strip()
        for line in vulnerable_code.splitlines()
        if len(line.strip()) >= 24
    ]
    selected = []
    for path in sorted(SUMMARIES.rglob("*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if (
                    TARGET_CWE in str(record.get("cwe_id", ""))
                    and record.get("summary")
                    and record.get("input_prompt")
                    and any(
                        anchor in record["input_prompt"] for anchor in code_anchors
                    )
                ):
                    record["source_file"] = str(path.relative_to(ROOT))
                    selected.append(record)
                    if len(selected) == SUMMARY_RECORD_LIMIT:
                        return selected
    pytest.skip(f"Fewer than {SUMMARY_RECORD_LIMIT} usable {TARGET_CWE} summaries found")


def _write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8")


def test_real_data_public_api_workflow(monkeypatch):
    if not RAW_DATA.is_file() or not SUMMARIES.is_dir():
        pytest.skip("The ignored raw dataset and mined summaries are not available")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    primevul_record = _read_real_primevul_record()
    summary_records = _read_real_summaries(primevul_record["func"])

    primevul_sample_path = ARTIFACTS / "primevul_sample.jsonl"
    primevul_sample_path.write_text(
        json.dumps(primevul_record) + "\n", encoding="utf-8"
    )
    (ARTIFACTS / "summary_samples.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in summary_records),
        encoding="utf-8",
    )

    dataset = PrimeVulLoader().load(
        primevul_sample_path,
        patch_column="func",
        vul_func_column="func",
    )
    assert len(dataset.examples) == 1
    example = dataset.examples[0]
    assert example.cve_id == primevul_record.get("cve")
    assert example.vulnerable_code
    assert TARGET_CWE in str(example.cwe_id)

    from mining.trees.utils import build_tree as tree_builder

    summary_patches = tree_builder.prepare_patches_from_summary_files(
        pd.DataFrame.from_records(summary_records)
    )
    assert len(summary_patches) == SUMMARY_RECORD_LIMIT
    reference_patch = str(summary_patches.iloc[0]["patch"]).strip()
    assert reference_patch

    guidance_calls = []

    def fake_get_llm(config):
        return object()

    def fake_generate_response(config, prompt):
        guidance_calls.append(prompt)
        return json.dumps(
            {
                "label": "Validate protocol boundaries",
                "summary": "A broad version check applies protocol behavior incorrectly.",
                "guidance": "Match behavior to the exact protocol version before selecting algorithms.",
            }
        )

    monkeypatch.setattr(tree_builder, "get_llm", fake_get_llm)
    monkeypatch.setattr(tree_builder, "generate_response", fake_generate_response)
    generated = GuidanceGenerator().generate(
        GuidanceGenerationRequest(
            patches=summary_patches,
            config=tree_builder.TreeConfig(
                min_group_size=2,
                max_group_size=2,
                force_merge_threshold=2,
                provider="openai",
                model="test-placeholder",
                tree_type="repair",
            ),
            cwe_id=TARGET_CWE,
        )
    )
    root, nodes, depth = generated
    assert guidance_calls
    assert root.guidance

    class FakeResponse:
        output_text = f"<repaired_code>{reference_patch}</repaired_code>"

    class FakeResponses:
        def __init__(self):
            self.calls = []

        def create(self, **kwargs):
            self.calls.append(kwargs)
            return FakeResponse()

    class FakeClient:
        def __init__(self):
            self.responses = FakeResponses()

    fake_client = FakeClient()
    repair_result = Repairer(
        LLMClient("openai", "test-placeholder", client=fake_client)
    ).repair(
        RepairRequest(
            vulnerable_code=example.vulnerable_code,
            guidance=root.guidance,
        )
    )
    assert fake_client.responses.calls
    assert repair_result.repaired_code == reference_patch

    evaluation_input = pd.DataFrame(
        [
            {
                "prompt_template": "zero_shot",
                "guidance_used": True,
                "ground_truth_patch": reference_patch,
                "extracted_patch": repair_result.repaired_code,
            }
        ]
    )
    evaluation = Evaluator().evaluate(evaluation_input)
    assert evaluation.overall["num_samples"] == 1
    assert evaluation.overall["patch_match_rate"] == 1.0

    _write_json(
        ARTIFACTS / "loaded_dataset_sample.json",
        {
            "name": dataset.name,
            "cve_id": example.cve_id,
            "cwe_id": example.cwe_id,
            "vulnerable_code": example.vulnerable_code,
        },
    )
    _write_json(
        ARTIFACTS / "guidance_tree.json",
        {
            "root_id": root.node_id,
            "depth": depth,
            "nodes": {
                node_id: tree_builder.node_to_dict(node)
                for node_id, node in nodes.items()
            },
        },
    )
    _write_json(ARTIFACTS / "repair_result.json", asdict(repair_result))
    evaluation_input.to_csv(ARTIFACTS / "evaluation_input.csv", index=False)
    _write_json(ARTIFACTS / "evaluation_result.json", evaluation.overall)

