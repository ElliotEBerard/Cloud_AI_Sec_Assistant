import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from Enrichment import ENRICHED_PATH, get_model_features

MODEL_DIR = './Models/'
SEED = 42
TEST_FRACTION = 0.3
N_TRAIN = 150000
FPR_LEVELS = (0.01, 0.05, 0.10)
# Time features and synthetic context stay out (schedule leakage); the hunting layer uses them.
# Port identity is left out: a network-wide baseline can't learn per-service ports.
DROP = ('port_category', 'service_port')

# python train_isolation_forest.py                   benign split by time
# python train_isolation_forest.py --random-benign   benign split at random (tests for drift)
BENIGN_RANDOM_SPLIT = '--random-benign' in sys.argv

pd.set_option('display.width', 250)
pd.set_option('display.max_columns', None)


def main():
    print(f'Random benign split: {BENIGN_RANDOM_SPLIT}')
    df = pd.read_parquet(ENRICHED_PATH)
    # Multi-packet flows only: single-packet flows carry no behavior for a baseline to learn
    df = df[(df['reply_stub'] == 0) & (df['single_packet'] == 0)].copy()

    cols = [c for c in get_model_features(df) if c not in DROP]
    X = df[cols].replace([np.inf, -np.inf], np.nan)
    leftover = X.select_dtypes(exclude='number').columns.tolist()
    assert not leftover, f'Non-numeric columns: {leftover}'

    benign = df[df['label'] == 'Benign'].sort_values('timestamp')
    if BENIGN_RANDOM_SPLIT:
        is_test = np.random.default_rng(SEED).random(len(benign)) < TEST_FRACTION
        b_train, b_test = benign[~is_test], benign[is_test]
    else:
        cut = int(len(benign) * (1 - TEST_FRACTION))
        b_train, b_test = benign.iloc[:cut], benign.iloc[cut:]
    if len(b_train) > N_TRAIN:
        b_train = b_train.sample(n=N_TRAIN, random_state=SEED)

    median = X.loc[b_train.index].median().fillna(0)
    Xf = X.fillna(median)
    assert not Xf.isna().any().any()

    model = IsolationForest(n_estimators=300, random_state=SEED, n_jobs=-1)
    model.fit(Xf.loc[b_train.index])

    score = pd.Series(-model.score_samples(Xf), index=df.index)   # higher = more anomalous
    ref = score[b_test.index]
    thresholds = {f: ref.quantile(1 - f) for f in FPR_LEVELS}
    print(f'Train: {len(b_train)} benign | Held-out benign: {len(b_test)} | Features: {len(cols)}')
    print('Thresholds (false-alarm rate -> score):', {f'{f:.0%}': round(t, 4) for f, t in thresholds.items()})

    rows = []
    for label, g in df[df['label'] != 'Benign'].groupby('label'):
        y = np.r_[np.zeros(len(ref)), np.ones(len(g))]
        s = np.r_[ref.to_numpy(), score[g.index].to_numpy()]
        row = {'label': label, 'n': len(g), 'auc': round(roc_auc_score(y, s), 3)}
        for f, t in thresholds.items():
            row[f'det@{f:.0%}'] = round(float((score[g.index] > t).mean()), 3)
        rows.append(row)
    print('\nAnomaly detection by attack class (never seen in training):')
    print(pd.DataFrame(rows).sort_values('auc').to_string(index=False))

    role = pd.Series('unused', index=benign.index)
    role[b_train.index] = 'train'
    role[b_test.index] = 'test'
    by_day = pd.DataFrame({'day': df.loc[benign.index, 'timestamp'].dt.date.to_numpy(),
                           'role': role.to_numpy(),
                           'score': score[benign.index].to_numpy()})
    print('\nBenign score by day and role (train rows are in-sample, so they read slightly low):')
    print(by_day.groupby(['day', 'role'])['score']
                .agg(n='count', median='median', p99=lambda s: s.quantile(0.99)).round(4))

    suffix = '_randbenign' if BENIGN_RANDOM_SPLIT else ''
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({'model': model, 'features': cols, 'median': median,
                 'thresholds': {float(f): float(t) for f, t in thresholds.items()},
                 'reference_scores': np.sort(ref.to_numpy()),
                 'multi_packet_only': True},
                f'{MODEL_DIR}isolation_forest{suffix}.joblib')
    print(f'\nSaved to {MODEL_DIR}isolation_forest{suffix}.joblib')


if __name__ == '__main__':
    main()