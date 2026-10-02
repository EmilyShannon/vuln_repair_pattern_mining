import json
import sqlite3

import pandas as pd
import pytest

from data.utils.dataset import analyze_dataset, load_dataset, split_dataset


def test_analyze_dataset_accepts_csv_and_jsonl(tmp_path):
    csv_path = tmp_path / "sample.csv"
    csv_df = pd.DataFrame(
        {
            "patch": ["patch1", "patch2"],
            "message": ["msg1", "msg2"],
            "vul_func": ["a", "b"],
            "fixed_func": ["c", "d"],
            "size": [10, 12],
            "cwe": ["CWE-79", "CWE-125"],
        }
    )
    csv_df.to_csv(csv_path, index=False)

    csv_output = tmp_path / "csv_output.csv"
    csv_plots = tmp_path / "plots_csv"
    csv_result = analyze_dataset(
        csv_path,
        csv_output,
        csv_plots,
        patch_column="patch",
        message_column="message",
        vul_func_column="vul_func",
        fixed_func_column="fixed_func",
        size_column="size",
        cwe_column="cwe",
        input_format="csv",
        dataset_name="sample_csv",
    )
    assert len(csv_result) == 2
    assert csv_output.exists()
    assert (tmp_path / "sample_csv_train.csv").exists()
    assert (tmp_path / "sample_csv_test.csv").exists()

    jsonl_path = tmp_path / "sample.jsonl"
    jsonl_records = [
        {
            "patch": "patch1",
            "message": "msg1",
            "vul_func": "a",
            "fixed_func": "c",
            "size": 10,
            "cwe": "CWE-79",
        },
        {
            "patch": "patch2",
            "message": "msg2",
            "vul_func": "b",
            "fixed_func": "d",
            "size": 12,
            "cwe": "CWE-125",
        },
    ]
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for record in jsonl_records:
            handle.write(json.dumps(record) + "\n")

    jsonl_output = tmp_path / "jsonl_output.csv"
    jsonl_plots = tmp_path / "plots_jsonl"
    jsonl_result = analyze_dataset(
        jsonl_path,
        jsonl_output,
        jsonl_plots,
        patch_column="patch",
        message_column="message",
        vul_func_column="vul_func",
        fixed_func_column="fixed_func",
        size_column="size",
        cwe_column="cwe",
        input_format="jsonl",
        dataset_name="sample_jsonl",
    )
    assert len(jsonl_result) == 2
    assert jsonl_output.exists()
    assert (tmp_path / "sample_jsonl_train.csv").exists()
    assert (tmp_path / "sample_jsonl_test.csv").exists()


def test_analyze_dataset_generates_patch_from_diff_when_patch_column_missing(tmp_path):
    csv_path = tmp_path / "no_patch.csv"
    csv_df = pd.DataFrame(
        {
            "message": ["msg1"],
            "vul_func": ["int x = 1;\nreturn x;"],
            "fixed_func": ["int x = 2;\nreturn x;"],
            "size": [3],
            "cwe": ["CWE-79"],
        }
    )
    csv_df.to_csv(csv_path, index=False)

    output_path = tmp_path / "generated_patch.csv"
    plots_dir = tmp_path / "plots_generated"
    result = analyze_dataset(
        csv_path,
        output_path,
        plots_dir,
        patch_column="patch",
        message_column="message",
        vul_func_column="vul_func",
        fixed_func_column="fixed_func",
        size_column="size",
        cwe_column="cwe",
        input_format="csv",
        dataset_name="generated_patch",
    )

    assert "patch" in result.columns
    generated_patch = result.iloc[0]["patch"]
    assert "---" in generated_patch
    assert "+++" in generated_patch
    assert "-int x = 1;" in generated_patch
    assert "+int x = 2;" in generated_patch


def test_custom_columns_and_size_are_normalized(tmp_path):
    csv_path = tmp_path / "custom.csv"
    pd.DataFrame(
        {
            "description": ["message"],
            "before_code": ["old\ncode"],
            "after_code": ["new\ncode"],
            "line_count": [2],
            "weakness_id": ["CWE-79"],
        }
    ).to_csv(csv_path, index=False)

    result = load_dataset(
        csv_path,
        message_column="description",
        vul_func_column="before_code",
        fixed_func_column="after_code",
        size_column="line_count",
        cwe_column="weakness_id",
    )

    assert result.loc[0, "message"] == "message"
    assert result.loc[0, "vul_func"] == "old\ncode"
    assert result.loc[0, "fixed_func"] == "new\ncode"
    assert result.loc[0, "size"] == 2
    assert result.loc[0, "cwe"] == "CWE-79"
    assert "-old" in result.loc[0, "patch"]
    assert "+new" in result.loc[0, "patch"]


def test_split_is_deterministic_and_keeps_singletons_in_train():
    df = pd.DataFrame(
        {
            "cwe": ["CWE-79"] * 5 + ["CWE-125"],
            "row": list(range(6)),
        }
    )

    train, test = split_dataset(df, random_state=7)
    train_again, test_again = split_dataset(df, random_state=7)

    assert len(train) + len(test) == len(df)
    assert train["row"].is_unique
    assert test["row"].is_unique
    assert set(train["row"]).isdisjoint(test["row"])
    assert set(train["row"]) | set(test["row"]) == set(df["row"])
    assert train.loc[train["cwe"] == "CWE-125", "row"].tolist() == [5]
    assert test.loc[test["cwe"] == "CWE-125"].empty
    pd.testing.assert_frame_equal(train, train_again)
    pd.testing.assert_frame_equal(test, test_again)


def test_split_accepts_multiple_cwes_per_row():
    df = pd.DataFrame(
        {
            "cwe": [
                ["CWE-79", "CWE-125"],
                ["CWE-79", "CWE-125"],
                ["CWE-79"],
            ],
            "row": [0, 1, 2],
        }
    )

    train, test = split_dataset(df)

    assert len(train) + len(test) == len(df)
    assert set(train["row"]) | set(test["row"]) == set(df["row"])
    assert set(train["row"]).isdisjoint(test["row"])


def test_load_dataset_reads_sqlite_table(tmp_path):
    db_path = tmp_path / "sample.db"
    with sqlite3.connect(db_path) as connection:
        pd.DataFrame(
            {"patch": ["change"], "cwe_id": ["CWE-79"]}
        ).to_sql("training", connection, index=False)

    result = load_dataset(db_path, table="training")

    assert result.loc[0, "patch"] == "change"
    assert result.loc[0, "cwe"] == "CWE-79"


def test_sqlite_input_requires_an_existing_table(tmp_path):
    db_path = tmp_path / "sample.db"
    with sqlite3.connect(db_path):
        pass
    with pytest.raises(ValueError, match="Table 'missing' not found"):
        load_dataset(db_path, table="missing")
