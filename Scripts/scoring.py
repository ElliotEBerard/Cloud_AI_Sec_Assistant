import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier
from Enrichment import ENRICHED_PATH, PARQUET_DIR, get_model_features
from train_supervised import build_matrix, WEB_ATTACKS, HOLDOUT_LABELS

SCORED_PATH = PARQUET_DIR + 'scored_events.parquet'
IF_PATH = './Models/isolation_forest.joblib'
N_FOLDS = 4
BENIGN_TRAIN_CAP = 100000
SEED = 42

pd.set_option('display.width', 250)
pd.set_option('display.max_columns', None)

KEEP = ['flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'label', 'target',
        'mitre_technique', 'mitre_tactic', 'port_category', 'asset_id', 'service_type',
        'asset_criticality', 'user_id', 'user_role', 'historical_alert_count',
        'reply_stub', 'single_packet', 'evidence', 'fold', 'pred_class', 'attack_prob',
        'pred_conf', 'anomaly_pct']

def main():
    df = pd.read_parquet(ENRICHED_PATH).reset_index(drop=True)

    # Build the feature list first, before this script adds columns of its own
    features = [c for c in get_model_features(df) if c != 'service_port']

    df['target'] = df['label'].replace({w: 'Web_Attack' for w in WEB_ATTACKS})
    df['evidence'] = np.where(df['reply_stub'] == 1, 'insufficient',
                              np.where(df['single_packet'] == 1, 'single_packet', 'multi_packet'))

    X_df = build_matrix(df, features)
    print(f'Feature matrix: {X_df.shape[1]} columns (the trained classifier uses 218)')
    X = X_df.to_numpy(dtype='float32')

    scorable = (df['reply_stub'] == 0).to_numpy()
    trainable = scorable & ~df['label'].isin(HOLDOUT_LABELS).to_numpy()

    # Contiguous time blocks within each class; a row is scored by a model trained on the other blocks
    t = df[trainable].sort_values('timestamp')
    rank = t.groupby('target').cumcount()
    size = t.groupby('target')['target'].transform('size')
    df['fold'] = -1
    df.loc[t.index, 'fold'] = (rank * N_FOLDS // size).astype(int)
    fold = df['fold'].to_numpy()

    le = LabelEncoder().fit(df.loc[trainable, 'target'])
    classes = list(le.classes_)
    benign_idx = classes.index('Benign')
    proba = np.full((len(df), len(classes)), np.nan, dtype='float32')
    # Non-trainable but scorable rows (Infiltration) get the average of the fold models
    extra = np.flatnonzero(scorable & ~trainable)
    proba[extra] = 0.0
    rng = np.random.default_rng(SEED)

    for k in range(N_FOLDS):
        tr = np.flatnonzero(trainable & (fold != k))
        te = np.flatnonzero(trainable & (fold == k))
        is_benign = (df['target'].to_numpy()[tr] == 'Benign')
        keep_benign = np.flatnonzero(is_benign)
        if len(keep_benign) > BENIGN_TRAIN_CAP:
            drop = rng.choice(keep_benign, size=len(keep_benign) - BENIGN_TRAIN_CAP, replace=False)
            tr = np.delete(tr, drop)
        y = le.transform(df['target'].to_numpy()[tr])

        model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8,
                              colsample_bytree=0.8, tree_method='hist', n_jobs=-1,
                              random_state=SEED, eval_metric='mlogloss')
        model.fit(X[tr], y, sample_weight=compute_sample_weight('balanced', y) ** 0.5)
        proba[te] = model.predict_proba(X[te])
        if len(extra):
            proba[extra] += model.predict_proba(X[extra]) / N_FOLDS
        print(f'Fold {k + 1}/{N_FOLDS} done | train {len(tr)} | scored {len(te)}')

    has = scorable
    df['pred_class'] = None
    df.loc[has, 'pred_class'] = np.array(classes)[proba[has].argmax(axis=1)]
    df['pred_conf'] = np.where(has, np.nanmax(proba, axis=1, initial=0), np.nan)
    df['attack_prob'] = np.where(has, 1 - proba[:, benign_idx], np.nan)

    # Isolation Forest percentile against the held-out benign reference (multi-packet flows only)
    art = joblib.load(IF_PATH)
    multi = np.flatnonzero((df['evidence'] == 'multi_packet').to_numpy())
    Xi = df.iloc[multi][art['features']].replace([np.inf, -np.inf], np.nan).fillna(art['median'])
    raw = -art['model'].score_samples(Xi)
    ref = art['reference_scores']
    df['anomaly_pct'] = np.nan
    df.loc[df.index[multi], 'anomaly_pct'] = np.searchsorted(ref, raw) / len(ref)

    out = df[[c for c in KEEP if c in df.columns]]
    os.makedirs(PARQUET_DIR, exist_ok=True)
    out.to_parquet(SCORED_PATH, index=False)
    print(f'\nWrote {SCORED_PATH}: {len(out)} rows')

    oof = df[df['fold'] >= 0]
    print('\nOut-of-fold accuracy by label:')
    print((oof['pred_class'] == oof['target']).groupby(oof['label']).mean().round(3))
    print('\nEvidence level by label (share of rows):')
    print(pd.crosstab(df['label'], df['evidence'], normalize='index').round(3))
    print('\nMean attack_prob and share of multi-packet flows above benign p90, by label:')
    hi = (df['anomaly_pct'] >= 0.9).where(df['anomaly_pct'].notna())
    print(pd.DataFrame({'attack_prob': df['attack_prob'].groupby(df['label']).mean().round(3),
                        'above_p90': hi.groupby(df['label']).mean().round(3)}))


if __name__ == '__main__':
    main()