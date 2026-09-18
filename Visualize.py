# find unnecessary columns based on data
import pandas as pd
import numpy as np

def count_labels(parquet_path):
    df = pd.read_parquet(parquet_path, columns=['label'])
    counts = df['label'].value_counts()
    pct = df['label'].value_counts(normalize=True).round(4) * 100
    
    summary = pd.DataFrame({'count': counts, 'percentage': pct})
    print(summary)
    print(f"\nTotal rows: {len(df)}")
    
    return summary

#count_labels('./Datasets/base_data.parquet')

def analyze_combined_columns(parquet_path, corr_threshold=0.9, dominant_threshold=0.98):
    df = pd.read_parquet(parquet_path)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    print(f"Total rows: {len(df)}, Total columns: {len(df.columns)}\n")
    
    # 1. Zero-variance / near-constant columns
    print("=" * 60)
    print("ZERO-VARIANCE / NEAR-CONSTANT COLUMNS")
    print("=" * 60)
    nunique = df.nunique()
    zero_var = nunique[nunique <= 1].index.tolist()
    print(f"Zero-variance (drop candidates): {zero_var}\n")
    
    dominant_cols = []
    for col in df.columns:
        if df[col].nunique() > 0:
            top_freq = df[col].value_counts(normalize=True).iloc[0]
            if top_freq > dominant_threshold:
                dominant_cols.append((col, round(top_freq * 100, 2)))
    print(f"Near-constant (>{dominant_threshold*100}% one value):")
    for col, pct in sorted(dominant_cols, key=lambda x: -x[1]):
        print(f"  {col}: {pct}%")
    
    # 2. Null percentage per column
    print("\n" + "=" * 60)
    print("NULL PERCENTAGES")
    print("=" * 60)
    null_pct = (df.isna().sum() / len(df) * 100).round(2)
    print(null_pct[null_pct > 0].sort_values(ascending=False))
    
    # 3. Infinite values
    print("\n" + "=" * 60)
    print("INFINITE VALUES")
    print("=" * 60)
    inf_counts = df[numeric_cols].apply(lambda x: np.isinf(x).sum())
    print(inf_counts[inf_counts > 0])
    
    # 4. High correlation pairs
    print("\n" + "=" * 60)
    print(f"HIGH CORRELATION PAIRS (> {corr_threshold})")
    print("=" * 60)
    corr = df[numeric_cols].corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    high_corr_pairs = []
    for col in upper.columns:
        for row in upper.index:
            val = upper.loc[row, col]
            if pd.notna(val) and val > corr_threshold:
                high_corr_pairs.append((row, col, round(val, 4)))
    high_corr_pairs.sort(key=lambda x: -x[2])
    for pair in high_corr_pairs:
        print(pair)
    
    # 5. Suggested drop list (conservative: only exact/near-exact duplicates + zero-variance)
    print("\n" + "=" * 60)
    print("SUGGESTED DROP CANDIDATES")
    print("=" * 60)
    exact_dupes = [(a, b, c) for a, b, c in high_corr_pairs if c >= 0.999]
    print(f"Near-exact duplicate pairs (>=0.999): {exact_dupes}")
    print(f"Zero-variance columns: {zero_var}")
    
    return {
        'zero_variance': zero_var,
        'dominant': dominant_cols,
        'null_pct': null_pct[null_pct > 0],
        'inf_counts': inf_counts[inf_counts > 0],
        'high_corr_pairs': high_corr_pairs
    }

results = analyze_combined_columns('./Datasets/base_data.parquet')
