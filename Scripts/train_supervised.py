import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from Enrichment import ENRICHED_PATH, get_model_features

MODEL_DIR = './Models/'
SEED = 42
TEST_FRACTION = 0.3
BENIGN_TRAIN_CAP = 100000   # set to None to train on all benign rows
WEB_ATTACKS = ['Brute_Force_Web', 'Brute_Force_XSS', 'SQL_Injection']
HOLDOUT_LABELS = ['Infiltration']   # 4 rows: kept for anomaly-model evaluation

# python train_supervised.py                  port features on, time split for every class
# python train_supervised.py --no-ports       ablation: no port features
# python train_supervised.py --random-benign  benign split randomly instead of by time
USE_PORT_FEATURES = '--no-ports' not in sys.argv
BENIGN_RANDOM_SPLIT = '--random-benign' in sys.argv

pd.set_option('display.width', 250)
pd.set_option('display.max_columns', None)


def load_data():
    df = pd.read_parquet(ENRICHED_PATH)
    df = df[df['reply_stub'] == 0]                       # stubs carry no behavior to classify
    df = df[~df['label'].isin(HOLDOUT_LABELS)].copy()
    df['target'] = df['label'].replace({w: 'Web_Attack' for w in WEB_ATTACKS})
    return df


def build_matrix(df, feature_cols):
    X = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    if 'port_category' in X.columns:
        X = pd.get_dummies(X, columns=['port_category'], dtype=int)
    leftover = X.select_dtypes(include='object').columns.tolist()
    assert not leftover, f'Non-numeric feature columns: {leftover}'
    return X


def time_split(df):
    # Last 30% of each class by time goes to test; attacks are single sessions,
    # so a random split of near-identical flows would overstate accuracy
    df = df.sort_values('timestamp')
    rank = df.groupby('target').cumcount()
    size = df.groupby('target')['target'].transform('size')
    is_test = (rank >= (size * (1 - TEST_FRACTION)).astype(int)).to_numpy().copy()

    if BENIGN_RANDOM_SPLIT:
        rng = np.random.default_rng(SEED)
        benign = (df['target'] == 'Benign').to_numpy()
        is_test[benign] = rng.random(benign.sum()) < TEST_FRACTION

    return df[~is_test], df[is_test]


def print_error_analysis(train, test, pred, le):
    test_out = test.assign(pred=le.inverse_transform(pred))
    test_out['correct'] = test_out['pred'] == test_out['target']
    errors = test_out[~test_out['correct']]

    print('\nMost common errors (true -> predicted):')
    print(errors.groupby(['target', 'pred']).size().sort_values(ascending=False).head(10))

    print('\nRecall by class and single-packet flag (1 = at most one packet in the flow):')
    print(test_out.groupby(['target', 'single_packet'])['correct'].agg(['mean', 'count']).round(3))

    print('\nBenign flagged as Web_Attack, by day:')
    print(errors[(errors['target'] == 'Benign') & (errors['pred'] == 'Web_Attack')]
          ['timestamp'].dt.date.value_counts())

    print('\nBenign rows by day, train vs test:')
    print('train', train[train['target'] == 'Benign']['timestamp'].dt.date.value_counts().to_dict())
    print('test ', test[test['target'] == 'Benign']['timestamp'].dt.date.value_counts().to_dict())


def main():
    print(f'Port features: {USE_PORT_FEATURES} | Random benign split: {BENIGN_RANDOM_SPLIT}')
    df = load_data()

    # service_port is dropped because the port_category dummies already carry it
    features = [c for c in get_model_features(df) if c not in ('target', 'service_port')]
    if not USE_PORT_FEATURES:
        features.remove('port_category')
    X = build_matrix(df, features)

    train, test = time_split(df)
    if BENIGN_TRAIN_CAP:
        benign = train[train['target'] == 'Benign']
        if len(benign) > BENIGN_TRAIN_CAP:
            train = pd.concat([train[train['target'] != 'Benign'],
                               benign.sample(n=BENIGN_TRAIN_CAP, random_state=SEED)])

    X_train, X_test = X.loc[train.index], X.loc[test.index]
    le = LabelEncoder()
    y_train = le.fit_transform(train['target'])
    y_test = le.transform(test['target'])

    print(f'Train: {len(train)} rows | Test: {len(test)} rows | Features: {X_train.shape[1]}')
    print('\nTrain class counts:')
    print(train['target'].value_counts())

    model = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1,
                          subsample=0.8, colsample_bytree=0.8, tree_method='hist',
                          n_jobs=-1, random_state=SEED, eval_metric='mlogloss')
    weights = compute_sample_weight('balanced', y_train) ** 0.5   # softer than full balancing
    model.fit(X_train, y_train, sample_weight=weights)

    pred = model.predict(X_test)
    print('\nPer-class results (test set):')
    print(classification_report(y_test, pred, target_names=le.classes_, digits=3))
    print('Confusion matrix (rows = true, columns = predicted):')
    print(pd.DataFrame(confusion_matrix(y_test, pred), index=le.classes_, columns=le.classes_))

    print_error_analysis(train, test, pred, le)

    proba = model.predict_proba(X_test)
    benign_idx = list(le.classes_).index('Benign')
    p_attack = 1 - proba[:, benign_idx]
    print('\nBinary attack-vs-benign ROC AUC:', round(roc_auc_score(y_test != benign_idx, p_attack), 4))

    imp = pd.Series(model.get_booster().get_score(importance_type='gain')).sort_values(ascending=False)
    print('\nTop 20 features by gain:')
    print(imp.head(20))

    suffix = '' if USE_PORT_FEATURES else '_noport'
    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save_model(f'{MODEL_DIR}xgb_classifier{suffix}.json')
    with open(f'{MODEL_DIR}classifier_meta{suffix}.json', 'w') as f:
        json.dump({'classes': list(le.classes_), 'features': list(X_train.columns),
                   'use_port_features': USE_PORT_FEATURES}, f)
    print(f'\nSaved model and metadata to {MODEL_DIR} (suffix: "{suffix}")')


if __name__ == '__main__':
    main()