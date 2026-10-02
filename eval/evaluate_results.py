import math
import pickle
import re
from collections import Counter
from difflib import SequenceMatcher
from difflib import unified_diff
from pathlib import Path
import pandas as pd
try:
    from codebleu import calc_codebleu
    CODEBLEU_AVAILABLE = True
except ImportError:
    calc_codebleu = None
    CODEBLEU_AVAILABLE = False
# from bleu importlist_bleu 
from nltk.translate.bleu_score import sentence_bleu, corpus_bleu
from nltk.translate.bleu_score import SmoothingFunction

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\w\s]")
KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "return",
    "break",
    "continue",
    "class",
    "struct",
    "def",
    "import",
    "from",
    "try",
    "except",
    "with",
    "and",
    "or",
    "not",
    "true",
    "false",
    "null",
    "void",
    "int",
    "char",
    "float",
    "double",
    "bool",
    "size_t",
    "uint",
    "const",
    "static",
    "new",
    "delete",
}


def _to_text(value):
    if pd.isna(value):
        return ""
    return str(value)


def _to_bool_mask(series):
    return series.astype(str).str.strip().str.lower().isin({"true", "1", "yes", "y"})


def _tokenize(text):
    return [token.lower() for token in TOKEN_RE.findall(_to_text(text))]


# def _tokenize_identifiers(text):
#     return [token.lower() for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", _to_text(text))]


# def _tokenize_keywords(text):
#     return [token.lower() for token in _tokenize_identifiers(text) if token.lower() in KEYWORDS]

def compute_diff(reference, candidate):
    ref = normalize_patch(reference).splitlines(keepends=True)
    cand = normalize_patch(candidate).splitlines(keepends=True)

    return "".join(
        unified_diff(
            ref,
            cand,
            fromfile="ground_truth",
            tofile="generated",
            lineterm=""
        )
    )

def compute_fuzzy_match(reference, candidate):
    ref = _to_text(reference).strip()
    cand = _to_text(candidate).strip()
    if not ref and not cand:
        return 1.0
    if not ref or not cand:
        return 0.0
    return SequenceMatcher(None, ref, cand).ratio()


# def compute_bleu(reference, candidate):
#     ref_tokens = _tokenize(reference)
#     cand_tokens = _tokenize(candidate)

#     if not ref_tokens or not cand_tokens:
#         return 0.0

#     precisions = []
#     for n in range(1, 5):
#         if len(cand_tokens) < n:
#             return 0.0
#         ref_ngrams = [tuple(ref_tokens[i : i + n]) for i in range(len(ref_tokens) - n + 1)]
#         cand_ngrams = [tuple(cand_tokens[i : i + n]) for i in range(len(cand_tokens) - n + 1)]
#         if not cand_ngrams:
#             return 0.0

#         counts = Counter(cand_ngrams)
#         clipped = 0
#         for gram, count in counts.items():
#             clipped += min(count, ref_ngrams.count(gram))
#         precision = clipped / len(cand_ngrams)
#         precisions.append(precision)

#     if not precisions or any(p <= 0 for p in precisions):
#         return 0.0

#     brevity_penalty = min(1.0, math.exp(1 - len(ref_tokens) / max(1, len(cand_tokens))))
#     bleu = brevity_penalty * math.exp(sum(math.log(p) for p in precisions) / len(precisions))
#     return float(max(0.0, min(1.0, bleu)))

def compute_bleu(reference, candidate):
    ref_tokens = _tokenize(reference)
    cand_tokens = _tokenize(candidate)
    if not ref_tokens or not cand_tokens:
        return 0.0
    try:
        return float(sentence_bleu([ref_tokens], cand_tokens, smoothing_function=SmoothingFunction().method4))
    except Exception as e:
        print(f"Error computing BLEU: {e}")
        return 0.0


def compute_codebleu(reference, candidate):
    if not CODEBLEU_AVAILABLE or calc_codebleu is None:
        return 0.0
    try:
        return float(calc_codebleu([reference], [candidate], lang="c", weights=(0.25, 0.25, 0.25, 0.25), tokenizer=None)["codebleu"])
    except Exception as e:
        print(f"Error computing CodeBLEU: {e}")
        return 0.0


def analyze_patch_match(df):
    """Compute exact-match and similarity statistics for a DataFrame."""

    if df.empty:
        return {
            "overall": {
                "patch_match_rate": None,
                "num_samples": 0,
                "num_matches": 0,
                "fuzzy_match_rate": None,
                "avg_bleu": None,
                "avg_codebleu": None,
            },
            "by_prompt": pd.DataFrame(),
            "by_guidance": pd.DataFrame(),
            "by_prompt_and_guidance": pd.DataFrame(),
            "patches": pd.DataFrame(),
        }

    # patch_match = _to_bool_mask(df.get("patch_match", pd.Series([False] * len(df))))
    patch_match = (
        df["ground_truth_patch"]
        .apply(normalize_patch)
        ==
        df["extracted_patch"]
        .apply(normalize_patch)
    )
    metric_rows = []
    for _, row in df.iterrows():
        reference = normalize_patch(row.get("ground_truth_patch", ""))
        candidate = normalize_patch(row.get("extracted_patch", ""))

        metric_rows.append(
            {
                "fuzzy_match": compute_fuzzy_match(reference, candidate),
                "bleu": compute_bleu(reference, candidate),
                "codebleu": compute_codebleu(reference, candidate),
            }
        )

    metrics_df = pd.DataFrame(metric_rows)

    summary_df = (
        df.assign(
            patch_match=patch_match,
            fuzzy_match=metrics_df["fuzzy_match"],
            bleu=metrics_df["bleu"],
            codebleu=metrics_df["codebleu"],
        )
    )

    summary_df["diff"] = summary_df.apply(
        lambda row: compute_diff(
            row["ground_truth_patch"],
            row["extracted_patch"]
        ),
        axis=1,
    )

    return {
        "overall": {
            "patch_match_rate": float(patch_match.mean()),
            "num_samples": len(df),
            "num_matches": int(patch_match.sum()),
            "fuzzy_match_rate": float(metrics_df["fuzzy_match"].mean()),
            "avg_bleu": float(metrics_df["bleu"].mean()),
            "avg_codebleu": float(metrics_df["codebleu"].mean()),
        },
        "by_prompt": (
            summary_df.groupby("prompt_template")
            .agg(
                patch_match_rate=("patch_match", "mean"),
                num_samples=("patch_match", "size"),
                num_matches=("patch_match", "sum"),
                fuzzy_match_rate=("fuzzy_match", "mean"),
                avg_bleu=("bleu", "mean"),
                avg_codebleu=("codebleu", "mean"),
            )
            .sort_values("patch_match_rate", ascending=False)
        ),
        "by_guidance": (
            summary_df.groupby("guidance_used")
            .agg(
                patch_match_rate=("patch_match", "mean"),
                num_samples=("patch_match", "size"),
                num_matches=("patch_match", "sum"),
                fuzzy_match_rate=("fuzzy_match", "mean"),
                avg_bleu=("bleu", "mean"),
                avg_codebleu=("codebleu", "mean"),
            )
            .sort_index()
        ),
        "by_prompt_and_guidance": (
            summary_df.groupby(["prompt_template", "guidance_used"])
            .agg(
                patch_match_rate=("patch_match", "mean"),
                num_samples=("patch_match", "size"),
                num_matches=("patch_match", "sum"),
                fuzzy_match_rate=("fuzzy_match", "mean"),
                avg_bleu=("bleu", "mean"),
                avg_codebleu=("codebleu", "mean"),
            )
            .sort_index()
        ),
        "patches": summary_df,
    }


# def normalize_patch(text):
#     text = _to_text(text)

#     # Normalize line endings
#     text = text.replace("\r\n", "\n").replace("\r", "\n")

#     # Strip whitespace from each line
#     lines = [line.rstrip() for line in text.split("\n")]

#     # Remove leading/trailing blank lines
#     while lines and lines[0] == "":
#         lines.pop(0)
#     while lines and lines[-1] == "":
#         lines.pop()

#     return "\n".join(lines)

def normalize_patch(text):
    text = _to_text(text).replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in text.splitlines()]
    lines = [re.sub(r"\s+", " ", line) for line in lines]
    lines = [re.sub(r"\s*([{}()\[\];,])\s*", r"\1", line) for line in lines]
    lines = [re.sub(r"\s*([+\-*/%<>=!&|^~]+)\s*", r"\1", line) for line in lines]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def main():
    results_folder_base = Path(__file__).parent.resolve() / "results"
    # TODO make this a command line arg
    dataset = "titanvul"
    mode = "test" 
    provider = "ollama"
    model_safe_name = "zerocopia_deepseek-v4-flash_cloud"
    results_folder = Path(f"{results_folder_base}/{dataset}/{mode}/{provider}/{model_safe_name}") 
    
    dfs_results = {}
    compiled_df = pd.DataFrame()


    # Go through all of the folders names {cwe-id}
    for cwe_folder in sorted(results_folder.iterdir()):
        if not cwe_folder.is_dir():
            continue

        csv_files = sorted(cwe_folder.glob("*.csv"))
        if not csv_files:
            print(f"Skipping empty folder: {cwe_folder}")
            continue

        cwe_id = cwe_folder.name.lower()
        dfs_results[cwe_id] = {
            "dfs": {},
            "analysis": {},
        }

        for csv_file in csv_files:
            print(f"Reading file: {csv_file}")
            condition = "guidance" if "no_guidance" not in csv_file.stem else "no_guidance"

            try:
                df = pd.read_csv(csv_file)
                df["cwe"] = cwe_id
                df["condition"] = condition
            except Exception as e:
                print(f"Problem with: {csv_file}")
                print(e)
                continue

            compiled_df = pd.concat([compiled_df, df], ignore_index=True)
            dfs_results[cwe_id]["dfs"][condition] = df
    # ---------------------------------------------------------------------
    # Load every CSV
    # ---------------------------------------------------------------------

    # for csv_file in sorted(results_folder.glob("*.csv")):
    #     print(f"Reading file: {csv_file}")
    #     match = re.match(r"^(cwe[-_]\d+)", csv_file.stem, re.IGNORECASE)
    #     if not match:
    #         continue

    #     cwe = match.group(1).lower().replace("_", "-")
    #     condition = "guidance" if "no_guidance" not in csv_file.stem else "no_guidance"

    #     try:
    #         df = pd.read_csv(csv_file)
    #         df["cwe"] = cwe
    #         df["condition"] = condition
    #         # print("PATCH MATCH COLUMN")
    #         # print(df["patch_match"].value_counts(dropna=False))
    #     except Exception as e:
    #         print(f"Problem with: {csv_file}")
    #         print(e)
    #         continue

    #     compiled_df = pd.concat([compiled_df, df], ignore_index=True)

    #     if cwe not in dfs_results:
    #         dfs_results[cwe] = {
    #             "dfs": {},
    #             "analysis": {},
    #         }

    #     dfs_results[cwe]["dfs"][condition] = df

    # ---------------------------------------------------------------------
    # Analyze each CWE
    # ---------------------------------------------------------------------

    for cwe, result in dfs_results.items():
        for condition, df in result["dfs"].items():
            result["analysis"][condition] = analyze_patch_match(df)

        combined_df = pd.concat(result["dfs"].values(), ignore_index=True)
        result["dfs"]["combined"] = combined_df
        result["analysis"]["combined"] = analyze_patch_match(combined_df)

    # ---------------------------------------------------------------------
    # Analyze all CWEs together
    # ---------------------------------------------------------------------

    guidance_mask = _to_bool_mask(compiled_df.get("guidance_used", pd.Series([False] * len(compiled_df))))

    dfs_results["all"] = {
        "dfs": {
            "combined": compiled_df,
            "guidance": compiled_df[guidance_mask],
            "no_guidance": compiled_df[~guidance_mask],
        },
        "analysis": {
            "combined": analyze_patch_match(compiled_df),
            "guidance": analyze_patch_match(compiled_df[guidance_mask]),
            "no_guidance": analyze_patch_match(compiled_df[~guidance_mask]),
        },
    }

    summary = []

    for cwe, result in dfs_results.items():
        if cwe == "all":
            continue

        for condition, analysis in result["analysis"].items():
            summary.append(
                {
                    "cwe": cwe,
                    "condition": condition,
                    "patch_match_rate": analysis["overall"]["patch_match_rate"],
                    "num_samples": analysis["overall"]["num_samples"],
                    "num_matches": analysis["overall"]["num_matches"],
                    "fuzzy_match_rate": analysis["overall"]["fuzzy_match_rate"],
                    "avg_bleu": analysis["overall"]["avg_bleu"],
                    "avg_codebleu": analysis["overall"]["avg_codebleu"],
                }
            )

    summary_df = pd.DataFrame(summary)

    print(summary_df)

    output_path = Path("dfs_results.pkl")

    with open(output_path, "wb") as f:
        pickle.dump(dfs_results, f)

    print(f"Saved results to {output_path}")

    print("Saving diff samples ")


    import random

    random.seed(42)

    SIMILARITY_BUCKETS = [
        (0.00, 0.20),
        (0.20, 0.40),
        (0.40, 0.60),
        (0.60, 0.80),
        (0.80, 0.85),
        (0.85, 0.90),
        (0.90, 0.95),
        (0.95, 0.99),
        (0.99, 1.01),   # includes exact matches
    ]
    samples = []
    patches = dfs_results["all"]["analysis"]["combined"]["patches"]
    for low, high in SIMILARITY_BUCKETS:

        bucket = patches[
            (patches["fuzzy_match"] >= low) &
            (patches["fuzzy_match"] < high)
        ]

        if bucket.empty:
            continue

        sample = bucket.sample(
            n=min(10, len(bucket)),
            random_state=42
        ).copy()

        sample["similarity_bucket"] = f"{low:.2f}-{high:.2f}"

        samples.append(sample)

    samples_df = pd.concat(samples, ignore_index=True)

    cols = [
        "cwe",
        "prompt_template",
        "guidance_used",
        "patch_match",
        "fuzzy_match",
        "bleu",
        "codebleu",
        "ground_truth_patch",
        "extracted_patch",
        "diff",
    ]

    samples_df[cols].to_csv(
        f"{results_folder}/patch_similarity_samples.csv",
        index=False,
    )
    print(f"Saved samples to {results_folder}/patch_similarity_samples.csv")
    # print("---------------------- GROUND TRUTH-----------------------------------")
    # print(compiled_df.iloc[5]["ground_truth_patch"][-66:])
    # print("------------------------PRODUCED PATCH---------------------------------")
    # print(compiled_df.iloc[5]["extracted_patch"][-66:])


    for bucket, group in samples_df.groupby("similarity_bucket"):
        print("=" * 100)
        print(f"SIMILARITY BUCKET: {bucket}")
        print("=" * 100)

        sample = group.iloc[0]

        print(f"CWE: {sample['cwe']}")
        print(f"Condition: {sample['condition']}")
        print(f"Prompt: {sample['prompt_template']}")
        print(f"Fuzzy similarity: {sample['fuzzy_match']:.4f}")
        print(f"BLEU: {sample['bleu']:.4f}")
        print(f"CodeBLEU: {sample['codebleu']:.4f}")
        print(f"Exact match: {sample['patch_match']}")

        print("\n--- DIFF ---")
        print(sample["diff"])

        print("\n")


    import matplotlib.pyplot as plt
    import numpy as np


    plot_dir = results_folder / "plots"
    plot_dir.mkdir(exist_ok=True)


    # -----------------------------------------------------------
    # Get patch-level dataframe
    # -----------------------------------------------------------

    patches = dfs_results["all"]["analysis"]["combined"]["patches"]


    # -----------------------------------------------------------
    # 1. Overall BLEU + fuzzy distributions
    # -----------------------------------------------------------

    plt.figure(figsize=(8, 5))

    plt.hist(
        patches["fuzzy_match"],
        bins=20,
        alpha=0.5,
        label="Fuzzy Match"
    )

    plt.hist(
        patches["bleu"],
        bins=20,
        alpha=0.5,
        label="BLEU"
    )

    plt.xlabel("Score")
    plt.ylabel("Number of patches")
    plt.title("Distribution of Patch Similarity Scores")
    plt.legend()

    plt.tight_layout()
    plt.savefig(
        plot_dir / "overall_similarity_distribution.png",
        dpi=300
    )
    plt.close()


    # -----------------------------------------------------------
    # 2. Per CWE distributions
    # -----------------------------------------------------------

    # Only keep CWEs with enough samples
    cwe_counts = patches["cwe"].value_counts()

    valid_cwes = cwe_counts[cwe_counts >= 5].index
    cwe_patches = patches[patches["cwe"].isin(valid_cwes)]

    codebleu_by_cwe = (
        cwe_patches
        .groupby(["cwe", "guidance_used"])["codebleu"]
        .mean()
        .unstack(fill_value=0)
        .reindex(valid_cwes)
    )

    if not codebleu_by_cwe.empty:
        plt.figure(figsize=(max(10, len(codebleu_by_cwe) * 0.5), 6))

        x = list(range(len(codebleu_by_cwe)))
        width = 0.35

        guidance_scores = codebleu_by_cwe.get(True, pd.Series(index=codebleu_by_cwe.index, data=0.0))
        no_guidance_scores = codebleu_by_cwe.get(False, pd.Series(index=codebleu_by_cwe.index, data=0.0))

        plt.bar(
            [xi - width / 2 for xi in x],
            guidance_scores,
            width,
            label="Guidance"
        )
        plt.bar(
            [xi + width / 2 for xi in x],
            no_guidance_scores,
            width,
            label="No Guidance"
        )

        plt.xticks(x, codebleu_by_cwe.index, rotation=90)
        plt.ylabel("Average CodeBLEU")
        plt.ylim(0, 1)
        plt.title("Average CodeBLEU by CWE: Guidance vs No Guidance")
        plt.legend()

        plt.tight_layout()
        plt.savefig(
            plot_dir / "codebleu_by_cwe_guidance_vs_no_guidance.png",
            dpi=300
        )
        plt.close()
    else:
        print("No valid CWEs available to plot average CodeBLEU by CWE.")


    # -----------------------------------------------------------
    # 3. Guidance vs no guidance
    # -----------------------------------------------------------

    guidance_results = dfs_results["all"]["analysis"]


    comparison = pd.DataFrame(
        {
            "Condition": [
                "Guidance",
                "No Guidance"
            ],
            "Exact Match": [
                guidance_results["guidance"]["overall"]["patch_match_rate"],
                guidance_results["no_guidance"]["overall"]["patch_match_rate"],
            ],
            "Fuzzy Similarity": [
                guidance_results["guidance"]["overall"]["fuzzy_match_rate"],
                guidance_results["no_guidance"]["overall"]["fuzzy_match_rate"],
            ],
            "BLEU": [
                guidance_results["guidance"]["overall"]["avg_bleu"],
                guidance_results["no_guidance"]["overall"]["avg_bleu"],
            ],
            "CodeBLEU": [
                guidance_results["guidance"]["overall"]["avg_codebleu"],
                guidance_results["no_guidance"]["overall"]["avg_codebleu"],
            ],
        }
    )


    print(comparison)


    # Plot grouped bars

    metrics = [
        "Exact Match",
        "Fuzzy Similarity",
        "BLEU",
        "CodeBLEU"
    ]

    x = np.arange(len(metrics))
    width = 0.35


    plt.figure(figsize=(10,5))

    plt.bar(
        x - width/2,
        comparison.iloc[0][metrics],
        width,
        label="Guidance"
    )

    plt.bar(
        x + width/2,
        comparison.iloc[1][metrics],
        width,
        label="No Guidance"
    )


    plt.xticks(
        x,
        metrics
    )

    plt.ylabel("Score")
    plt.ylim(0,1)
    plt.title("Guidance vs No Guidance")
    plt.legend()

    plt.tight_layout()

    plt.savefig(
        plot_dir / "guidance_vs_no_guidance.png",
        dpi=300
    )

    plt.close()


    # -----------------------------------------------------------
    # 4. Exact match rate per CWE by guidance vs no guidance

    exact_match_by_cwe = (
        cwe_patches
        .groupby(["cwe", "guidance_used"])["patch_match"]
        .mean()
        .unstack(fill_value=0)
        .reindex(valid_cwes)
    )

    if not exact_match_by_cwe.empty:
        plt.figure(figsize=(max(10, len(exact_match_by_cwe) * 0.5), 6))

        guidance_scores = exact_match_by_cwe.get(True, pd.Series(index=exact_match_by_cwe.index, data=0.0))
        no_guidance_scores = exact_match_by_cwe.get(False, pd.Series(index=exact_match_by_cwe.index, data=0.0))

        plt.bar(
            [xi - width / 2 for xi in x],
            guidance_scores,
            width,
            label="Guidance"
        )
        plt.bar(
            [xi + width / 2 for xi in x],
            no_guidance_scores,
            width,
            label="No Guidance"
        )

        plt.xticks(x, exact_match_by_cwe.index, rotation=90)
        plt.ylabel("Exact Match Rate")
        plt.ylim(0, 1)
        plt.title("Exact Match Rate by CWE: Guidance vs No Guidance")
        plt.legend()

        plt.tight_layout()
        plt.savefig(
            plot_dir / "exact_match_by_cwe_guidance_vs_no_guidance.png",
            dpi=300
        )
        plt.close()
    else:
        print("No valid CWEs available to plot exact match rate by CWE.")


    print(f"Saved plots to {plot_dir}")

if __name__ == "__main__":
    main()