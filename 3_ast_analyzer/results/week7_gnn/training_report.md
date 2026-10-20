# Week 7 CPG GNN Training Report

> **Run status: INCOMPLETE — no trained checkpoint or evaluation metrics**
>
> This report records the dataset and configuration used in the attempted run.
> The run stopped during feature preparation, before the first training epoch.
> It must not be presented as a successfully trained or evaluated model.

## At a glance

| Item | Verified result |
| --- | --- |
| Training outcome | Incomplete; 0 epochs completed |
| Dataset source | Local PyCode-Vul CSV files; not a Hugging Face streaming run |
| Prepared training CSV | `3_ast_analyzer/data/pycode_vul/prepared/train.csv` |
| Held-out test CSV | `3_ast_analyzer/data/pycode_vul/test.csv` |
| Training examples prepared for encoding | 26,007 CPG graphs reported by the run |
| CodeBERT graphs encoded before stop | 32 of 26,007 |
| Model checkpoint | `3_ast_analyzer/src/ml/cpg_gnn_model.pt` — not created |
| Final train/validation/test loss | Not available |
| Final accuracy, precision, recall, F1 | Not available |

## What was intended to be trained

The target was a binary vulnerability classifier over Python Code Property
Graphs (CPGs):

1. Build AST, approximate control-flow, and lexical data-flow edges from each
   valid Python function.
2. Embed graph nodes with the locally downloaded `microsoft/codebert-base`
   encoder (768-dimensional CodeBERT hidden states).
3. Classify each graph with AutoForge's four-layer, relation-aware GINE-style
   PyTorch model, which projects node representations to 128 dimensions and
   pools node features to a graph-level prediction.

The graph model uses native PyTorch message passing; PyTorch Geometric is not
required. CodeBERT weights were downloaded, but that alone does not mean the
GNN was trained.

## Dataset and preparation

| Detail | Value |
| --- | --- |
| Dataset | [S-AIR-L/PyCode-Vul](https://huggingface.co/datasets/S-AIR-L/PyCode-Vul) |
| Dataset license | CC-BY-4.0; retain attribution and comply with the dataset terms |
| Acquisition used for this run | Local CSVs; no streaming dataset loader was used |
| Original training CSV | `3_ast_analyzer/data/pycode_vul/train.csv` (14,248 rows) |
| Prepared training CSV | `3_ast_analyzer/data/pycode_vul/prepared/train.csv` (12,764 rows) |
| Official held-out test CSV | `3_ast_analyzer/data/pycode_vul/test.csv` (3,563 rows) |
| Prepared row labels | 5,381 label `1`; 7,383 label `0` |
| Exact-source overlap after preparation | 0 shared code hashes between prepared train and held-out test |

The prepared training set removes exact source-code overlap with the held-out
test set and duplicate training rows. The manifest records 502 removed
overlapping training rows and 982 removed duplicate training rows. The loader
also expands vulnerable/patched function pairs into graph examples and skips
empty, repeated-within-pair, or Python syntax-invalid functions. Its run log
records 153 empty cells, 2,854 duplicate source/patch pairs, and 77 invalid
functions skipped while loading the prepared training CSV.

The held-out CSV is separate from training. The trainer makes a grouped,
stratified train/validation/test split from its training examples and, when the
official test CSV is supplied, uses that CSV for final test evaluation.

## Training configuration

These are the configured values in the trainer; because the run did not reach
an epoch, they are not evidence of completed optimization.

| Setting | Configured value |
| --- | --- |
| Maximum epochs | 50 |
| Early-stopping patience | 7 epochs |
| Batch size | 32 |
| Optimizer | AdamW |
| Learning rate | 0.001 |
| Weight decay | 0.0001 |
| Loss | Binary cross-entropy with logits and positive-class weighting |
| Random seed | 42 |
| Runtime device | CPU (installed PyTorch was CPU-only) |

## Results

| Metric | Result |
| --- | --- |
| Epochs completed | **0** |
| Final training loss | **N/A — no epoch completed** |
| Validation loss / accuracy / precision / recall / F1 | **N/A — no validation pass** |
| Held-out test loss / accuracy / precision / recall / F1 | **N/A — no test evaluation** |
| Checkpoint saved | **No** |

The process encoded only 32 of the 26,007 graphs needed for feature
preparation. It was stopped before training rather than report partial
preprocessing as a model result. In particular, do not quote an accuracy,
loss, confidence score, or claim that the CPG GNN was trained from this run.

## Why the run stopped

- PyTorch in the project virtual environment was `2.13.0+cpu`, and
  `torch.cuda.is_available()` was false.
- The machine detected an NVIDIA GeForce RTX 2050 with 4 GB VRAM, but the
  installed PyTorch build could not use it.
- Available physical RAM measured during preflight was about 0.66 GB.
- Attempts to obtain a CUDA-enabled PyTorch wheel repeatedly stalled or failed
  with DNS/download interruptions and were cancelled. CPU-only PyTorch was
  left installed.
- The CPU feature-encoding pass was too slow for the full dataset under the
  available memory/runtime constraints.

## Reproducing a future training run

From the analyzer directory, after installing a compatible PyTorch build and
having enough working memory:

```powershell
python -m src.ml.cpg_training `
  --dataset data\pycode_vul\prepared\train.csv `
  --test-dataset data\pycode_vul\test.csv `
  --checkpoint src\ml\cpg_gnn_model.pt `
  --epochs 50 `
  --patience 7
```

After a successful run, regenerate this report with the actual epoch history,
held-out metrics, runtime, device, and checkpoint verification. Do not replace
the `N/A` entries with estimates or partial-run timings.

## Evidence files

- Machine-readable run status: [`training_status.json`](./training_status.json)
- Attempt log: [`training.log`](./training.log)
- Dataset preparation details: [`manifest.json`](../../data/pycode_vul/prepared/manifest.json)
- Trainer implementation: [`cpg_training.py`](../../src/ml/cpg_training.py)
- CPG GNN implementation: [`cpg_gnn.py`](../../src/ml/cpg_gnn.py)
