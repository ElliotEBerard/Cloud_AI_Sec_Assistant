# find unnecessary columns based on data
import pandas as pd
import numpy as np
import sys

def visualize_data(input):
    df = pd.read_csv(input, header=0, encoding="utf-8", low_memory=False)

    # check mixed data type (bot file had error)
    for col in ['handshake_duration']:
        print(col, "dtype:", df[col].dtype)
        print(df[col].apply(type).value_counts())
        print(df[col].unique()[:20])  
        print("---")

    # check invalid values
    for col in ['handshake_duration']:
        numeric = pd.to_numeric(df[col], errors='coerce')
        n_invalid = numeric.isna().sum() - df[col].isna().sum() 
        print(col, "invalid non-numeric values:", n_invalid, "out of", len(df))

    #check null values
    null_counts = df.isna().sum()
    null_pct = (null_counts / len(df) * 100).round(2)
    print(null_pct[null_pct > 0].sort_values(ascending=False))

    #Check infinite values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_counts = df[numeric_cols].apply(lambda x: np.isinf(x).sum())
    print(inf_counts[inf_counts > 0])

    #check negative values
    should_be_nonneg = ['duration', 'packets_count', 'total_payload_bytes', 'bytes_rate', 'packets_rate']
    for col in should_be_nonneg:
        n_neg = (df[col] < 0).sum()
        print(col, "negative values:", n_neg)

    # Check duplicates
    print("duplicate rows:", df.duplicated().sum())

    #test variance
    nunique = df.nunique()
    zero_var = nunique[nunique == 1]
    print("zero-variance columns:", list(zero_var.index))

    for col in df.columns:
        top_freq = df[col].value_counts(normalize=True).iloc[0] if df[col].nunique() > 0 else 0
        if top_freq > 0.98:
            print(col, "dominant value pct:", round(top_freq*100, 2))

    #check correlation
    corr = df[numeric_cols].corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    high_corr = [(col, row, upper.loc[row, col]) 
                for col in upper.columns for row in upper.index 
                if upper.loc[row, col] > 0.9]
    for c in high_corr:
        print(c)


if __name__ == "__main__":
    visualize_data(sys.argv[1])