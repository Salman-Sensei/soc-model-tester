# Model Development Notebook

This directory contains the Jupyter notebook used to develop and evaluate the network intrusion classification models supporting SOC Model Tester.

## Notebook

**`soc_intrusion_detection_pipeline.ipynb`**

The notebook covers:

- Data preparation and quality auditing for CIC-IDS2017 and UNSW-NB15.
- Alignment of seven shared network-flow features.
- Exploratory data analysis and label distribution analysis.
- Train/test splitting and fitted preprocessing.
- Baseline, logistic regression, weighted logistic regression, and Random Forest comparisons.
- Binary attack detection and attack-family classification.
- Provisional SOC triage thresholds and severity-related analysis.
- Evaluation metrics, confusion matrices, and inference tests.
- Model artifact preparation and integration considerations.

## Shared Feature Schema

The model uses the following seven input features in order:

1. `flow_duration_seconds`
2. `src_packets`
3. `dst_packets`
4. `src_bytes`
5. `dst_bytes`
6. `src_mean_packet_bytes`
7. `dst_mean_packet_bytes`

Ground-truth labels and dataset metadata are excluded from model inputs.

## Reproducibility

Run the notebook cells sequentially in Google Colab or a compatible Jupyter environment. Confirm the required dataset access, library versions, and preprocessing artifacts before running model training or inference.

Dataset files and serialized model artifacts are not committed as part of the notebook source. Follow the relevant dataset access terms and obtain the required files from their authorized sources.

## Evaluation Notes

Reported performance depends on the dataset version, split, preprocessing, and fitted estimator. Synthetic UI test records are intended for functionality checks, not for evaluating real-world model performance.

The SOC triage thresholds are provisional demonstration settings and should not be treated as calibrated operational policies.
