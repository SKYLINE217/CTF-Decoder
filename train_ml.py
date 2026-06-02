"""
CTF Decoder - ML Model Training Runner
======================================
Generates a large synthetic dataset of 50,000+ encoded CTF samples,
extracts statistical features and character-level TF-IDF n-grams,
and trains a custom RandomForest + ExtraTrees Ensemble.

Usage:
    python train_ml.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from ctf_decoder.detection.ml_dataset import generate_dataset
from ctf_decoder.detection.ml_model import extract_features, get_string_rep, MLModelManager
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box as rbox

def main():
    console = Console()
    console.print("\n[bold cyan]═" * 70)
    console.print("  CTF DECODER — HEAVY MACHINE LEARNING TRAINING SUITE")
    console.print("═" * 70 + "\n")
    
    # 1. Dataset Generation
    sample_count = 50000
    console.print(f"[*] Generating synthetic CTF dataset ({sample_count} samples)...")
    start_time = time.time()
    raw_data = generate_dataset(sample_count)
    gen_time = time.time() - start_time
    console.print(f"[+] Dataset generated successfully in [yellow]{gen_time:.2f}s[/yellow].")
    
    # Show distribution of classes
    distribution = {}
    for _, label in raw_data:
        distribution[label] = distribution.get(label, 0) + 1
        
    dist_table = Table(title="Class Distribution", box=rbox.SIMPLE_HEAVY, header_style="bold magenta")
    dist_table.add_column("Codec / Target Class")
    dist_table.add_column("Count", justify="right")
    dist_table.add_column("Proportion", justify="right")
    for label, count in sorted(distribution.items(), key=lambda x: -x[1]):
        dist_table.add_row(label, str(count), f"{count/len(raw_data):.1%}")
    console.print(dist_table)
    
    # 2. Feature Extraction
    console.print("\n[*] Extracting numerical statistics and string representations...")
    X_num = []
    X_str = []
    y = []
    
    start_time = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Extracting...", total=len(raw_data))
        for data_bytes, label in raw_data:
            features = extract_features(data_bytes)
            text_rep = get_string_rep(data_bytes)
            X_num.append(features)
            X_str.append(text_rep)
            y.append(label)
            progress.advance(task)
            
    feat_time = time.time() - start_time
    console.print(f"[+] Extracted features for {len(X_num)} samples in [yellow]{feat_time:.2f}s[/yellow].")
    
    # 3. Model Training
    console.print("\n[*] Training Heavy Custom Ensemble (RF + ET) heavily...")
    start_time = time.time()
    results = MLModelManager.train_and_save(X_num, X_str, y, estimators=300)
    train_time = time.time() - start_time
    console.print(f"[+] Training and serialization finished in [yellow]{train_time:.2f}s[/yellow].")
    
    # 4. Display Classification Report
    console.print("\n[bold cyan]═" * 70)
    console.print("  CLASSIFICATION REPORT (VALIDATION SET)")
    console.print("═" * 70 + "\n")
    
    report_table = Table(title="Evaluation Metrics", box=rbox.SIMPLE_HEAVY, header_style="bold green")
    report_table.add_column("Class")
    report_table.add_column("Precision", justify="right")
    report_table.add_column("Recall", justify="right")
    report_table.add_column("F1-Score", justify="right")
    report_table.add_column("Support", justify="right")
    
    rep = results["report"]
    for label, metrics in sorted(rep.items()):
        if label in ["accuracy", "macro avg", "weighted avg"]:
            continue
        report_table.add_row(
            label,
            f"{metrics['precision']:.3f}",
            f"{metrics['recall']:.3f}",
            f"{metrics['f1-score']:.3f}",
            str(int(metrics['support']))
        )
        
    report_table.add_section()
    report_table.add_row(
        "Accuracy",
        "",
        "",
        f"[bold green]{results['accuracy']:.3%}[/bold green]",
        str(int(rep['weighted avg']['support']))
    )
    report_table.add_row(
        "Macro Avg",
        f"{rep['macro avg']['precision']:.3f}",
        f"{rep['macro avg']['recall']:.3f}",
        f"{rep['macro avg']['f1-score']:.3f}",
        str(int(rep['macro avg']['support']))
    )
    report_table.add_row(
        "Weighted Avg",
        f"{rep['weighted avg']['precision']:.3f}",
        f"{rep['weighted avg']['recall']:.3f}",
        f"{rep['weighted avg']['f1-score']:.3f}",
        str(int(rep['weighted avg']['support']))
    )
    
    console.print(report_table)
    console.print("\n[bold green][✔] Heavy Custom Ensemble trained and verified successfully![/bold green]\n")

if __name__ == "__main__":
    main()
