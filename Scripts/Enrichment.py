import os
import sys
import numpy as np
import pandas as pd

SEED = 42
PARQUET_DIR = 'C:/parquets/'
REDUCED_PATH = PARQUET_DIR + 'base_data_reduced.parquet'
ENRICHED_PATH = PARQUET_DIR + 'base_data_enriched.parquet'
ASSETS_PATH = PARQUET_DIR + 'assets.parquet'
USERS_PATH = PARQUET_DIR + 'users.parquet'

# DoS_SlowHTTP medians match Brute_Force_FTP and all its rows are on port 21, so the class is unusable
DROP_LABELS = ['DoS_SlowHTTP']

PORT_CATEGORIES = {21: 'FTP', 22: 'SSH', 23: 'TELNET', 80: 'HTTP', 135: 'RPC', 139: 'NETBIOS',
                   443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3128: 'PROXY', 3306: 'MYSQL',
                   3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-ALT'}

PORT_TO_SERVICE = {'FTP': 'file_server', 'SMB': 'file_server', 'NETBIOS': 'file_server',
                   'SSH': 'ssh_server', 'HTTP': 'web_server', 'HTTPS': 'web_server',
                   'HTTP-ALT': 'web_server', 'MSSQL': 'database_server', 'MYSQL': 'database_server',
                   'TELNET': 'network_device', 'PROXY': 'network_device',
                   'RDP': 'workstation', 'VNC': 'workstation', 'RPC': 'workstation'}

# label -> (technique, tactic); verify IDs against attack.mitre.org before the write-up
MITRE_MAP = {
    'Benign':          ('none',  'none'),
    'Brute_Force_SSH': ('T1110', 'credential_access'),
    'Brute_Force_FTP': ('T1110', 'credential_access'),
    'Brute_Force_Web': ('T1110', 'credential_access'),
    'Brute_Force_XSS': ('T1190', 'initial_access'),
    'SQL_Injection':   ('T1190', 'initial_access'),
    'DoS_HULK':        ('T1499', 'impact'),
    'DoS_Golden_Eye':  ('T1499', 'impact'),
    'DoS_Slowloris':   ('T1499', 'impact'),
    'DoS_SlowHTTP':    ('T1499', 'impact'),
    'DDoS_HOIC':       ('T1498', 'impact'),
    'DDoS_LOIC_HTTP':  ('T1498', 'impact'),
    'Bot':             ('T1071', 'command_and_control'),
    'Infiltration':    ('T1203', 'execution'),
}

# Which asset type each attack label targets
LABEL_TARGET_TYPE = {
    'Brute_Force_SSH': 'ssh_server', 'Brute_Force_FTP': 'file_server',
    'Brute_Force_Web': 'web_server', 'Brute_Force_XSS': 'web_server', 'SQL_Injection': 'web_server',
    'DoS_HULK': 'web_server', 'DoS_Golden_Eye': 'web_server', 'DoS_Slowloris': 'web_server',
    'DoS_SlowHTTP': 'web_server', 'DDoS_HOIC': 'web_server', 'DDoS_LOIC_HTTP': 'web_server',
    'Bot': 'workstation', 'Infiltration': 'workstation',
}
N_TARGETS = 5

REQUIRED_INPUT = ['timestamp', 'dst_port', 'src_port', 'handshake_duration',
                  'fwd_packets_count', 'bwd_packets_count', 'direction_swapped', 'label']

# Columns that identify the label by construction or schedule. Keep them out of the classifier.
# Use them for scoring, per-entity baselining and the hunting layer instead.
MODEL_EXCLUDE = [
    'label', 'flow_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'hour_of_day', 'day_of_week',
    'asset_id', 'user_id', 'service_type', 'asset_criticality', 'user_role',
    'historical_alert_count', 'historical_alert_count_log',
    'mitre_technique', 'mitre_tactic',
    'flow_reversed', 'reply_stub', 'single_packet', 'direction_swapped',
]


def get_model_features(df):
    return [c for c in df.columns if c not in MODEL_EXCLUDE]


def add_time_and_handshake(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour_of_day'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['handshake_complete'] = df['handshake_duration'].notna().astype(int)
    return df


def add_port_category(df):
    # Direction was normalized in filtering.py, so dst_port is the service side for full flows.
    # flow_reversed now only marks reply stubs, which are deliberately left unswapped.
    dst = df['dst_port'].to_numpy()
    src = df['src_port'].to_numpy()
    known = list(PORT_CATEGORIES)
    dst_known = np.isin(dst, known)
    src_known = np.isin(src, known)
    df['service_port'] = np.where(dst_known, dst, np.where(src_known, src, dst))
    df['port_category'] = df['service_port'].map(PORT_CATEGORIES).fillna('unknown/ephemeral')
    df['flow_reversed'] = (~dst_known & src_known).astype(int)
    return df


def add_reply_stub(df):
    # One-packet replies from the service side (0 forward packets). Analysis flag, not a model input.
    df['reply_stub'] = (df['fwd_packets_count'] == 0).astype(int)
    return df


def add_single_packet(df):
    # Flows with at most one packet in total (lone replies, lone forward packets, lone resets).
    # Analysis flag for sliced reporting and for the Isolation Forest filter, not a model input.
    df['single_packet'] = ((df['fwd_packets_count'] + df['bwd_packets_count']) <= 1).astype(int)
    return df


def add_mitre(df):
    unmapped = set(df['label'].unique()) - set(MITRE_MAP)
    if unmapped:
        raise ValueError(f'Labels missing from MITRE_MAP: {unmapped}')
    df['mitre_technique'] = df['label'].map({k: v[0] for k, v in MITRE_MAP.items()})
    df['mitre_tactic'] = df['label'].map({k: v[1] for k, v in MITRE_MAP.items()})
    return df


def build_pools():
    asset_counts = {'workstation': 70, 'web_server': 16, 'file_server': 8,
                    'ssh_server': 10, 'database_server': 8, 'network_device': 8}
    criticality = {'workstation': 'low', 'web_server': 'medium', 'file_server': 'medium',
                   'ssh_server': 'high', 'database_server': 'high', 'network_device': 'medium'}

    roles = ['standard_user'] * 56 + ['admin'] * 10 + ['service_account'] * 14
    users = pd.DataFrame({'user_id': [f'user_{i:04d}' for i in range(len(roles))],
                          'user_role': roles})
    owners = users.loc[users['user_role'] != 'service_account', 'user_id'].to_numpy()

    rows, ws_count = [], 0
    for stype, n in asset_counts.items():
        for _ in range(n):
            owner = None
            if stype == 'workstation':
                owner = owners[ws_count % len(owners)]
                ws_count += 1
            rows.append({'asset_id': f'asset_{len(rows):05d}', 'service_type': stype,
                         'asset_criticality': criticality[stype], 'owner_user_id': owner})
    return pd.DataFrame(rows), users


def add_assets_and_users(df, assets, users, seed=SEED):
    rng = np.random.default_rng(seed)
    by_type = {t: g['asset_id'].to_numpy() for t, g in assets.groupby('service_type')}

    labels = df['label'].to_numpy()
    present = set(np.unique(labels))
    targets = {label: rng.choice(by_type[stype], size=min(N_TARGETS, len(by_type[stype])), replace=False)
               for label, stype in LABEL_TARGET_TYPE.items() if label in present}

    ports = df['port_category'].to_numpy()
    asset_ids = np.empty(len(df), dtype=object)

    for label, ids in targets.items():
        mask = labels == label
        asset_ids[mask] = rng.choice(ids, size=mask.sum())

    benign = labels == 'Benign'
    for cat in np.unique(ports[benign]):
        mask = benign & (ports == cat)
        stype = PORT_TO_SERVICE.get(cat)
        pool = by_type[stype] if stype else assets['asset_id'].to_numpy()
        asset_ids[mask] = rng.choice(pool, size=mask.sum())

    if pd.isna(asset_ids).any():
        raise ValueError('Some rows were not assigned an asset (unexpected label?)')

    df['asset_id'] = asset_ids
    asset_idx = assets.set_index('asset_id')
    df['service_type'] = df['asset_id'].map(asset_idx['service_type'])
    df['asset_criticality'] = df['asset_id'].map(asset_idx['asset_criticality'])

    df['user_id'] = df['asset_id'].map(asset_idx['owner_user_id'])
    need_user = df['user_id'].isna()
    privileged = users.loc[users['user_role'].isin(['admin', 'service_account']), 'user_id'].to_numpy()
    df.loc[need_user, 'user_id'] = rng.choice(privileged, size=need_user.sum())
    df['user_role'] = df['user_id'].map(users.set_index('user_id')['user_role'])
    return df


def add_historical_alert_count(df, window='24h'):
    df = df.sort_values(['asset_id', 'timestamp']).reset_index(drop=True)
    df['_is_alert'] = (df['label'] != 'Benign').astype(int)
    counts = (df.groupby('asset_id')
                .rolling(window, on='timestamp', closed='left')['_is_alert'].sum())
    assert len(counts) == len(df)
    df['historical_alert_count'] = counts.fillna(0).to_numpy().astype(int)
    df['historical_alert_count_log'] = np.log1p(df['historical_alert_count'])
    return df.drop(columns='_is_alert')


def enrich():
    df = pd.read_parquet(REDUCED_PATH)
    missing = [c for c in REQUIRED_INPUT if c not in df.columns]
    assert not missing, f'Reduced file is missing required columns: {missing}'

    if DROP_LABELS:
        df = df[~df['label'].isin(DROP_LABELS)].reset_index(drop=True)

    assets, users = build_pools()
    df = add_time_and_handshake(df)
    df = add_port_category(df)
    df = add_reply_stub(df)
    df = add_single_packet(df)
    df = add_mitre(df)
    df = add_assets_and_users(df, assets, users)
    df = add_historical_alert_count(df)

    os.makedirs(PARQUET_DIR, exist_ok=True)
    df.to_parquet(ENRICHED_PATH, index=False)
    assets.to_parquet(ASSETS_PATH, index=False)
    users.to_parquet(USERS_PATH, index=False)
    return df


def validate(df):
    new_cols = ['hour_of_day', 'day_of_week', 'handshake_complete', 'service_port', 'port_category',
                'flow_reversed', 'reply_stub', 'single_packet', 'direction_swapped',
                'mitre_technique', 'mitre_tactic', 'asset_id', 'service_type', 'asset_criticality',
                'user_id', 'user_role', 'historical_alert_count', 'historical_alert_count_log']
    missing = [c for c in new_cols if c not in df.columns]
    assert not missing, f'Missing columns: {missing}'
    nulls = df[new_cols].isna().sum()
    assert nulls.sum() == 0, f'Nulls in enriched columns:\n{nulls[nulls > 0]}'

    print(f'Rows: {len(df)} | Columns: {len(df.columns)}')
    print('\nLabel counts:')
    print(df['label'].value_counts())

    print('\nPort category by label (top 3 per label):')
    for label, g in df.groupby('label'):
        print(f'  {label}: {g["port_category"].value_counts().head(3).to_dict()}')

    print('\nShare of one-packet reply stubs, by label:')
    print(df.groupby('label')['reply_stub'].mean().round(3))

    print('\nShare of single-packet flows (any direction), by label:')
    print(df.groupby('label')['single_packet'].mean().round(3))

    print('\nShare of rows direction-normalized, by label:')
    print(df.groupby('label')['direction_swapped'].mean().round(3))

    print('\nShare still flagged flow_reversed (should track the stub share):')
    print(df.groupby('label')['flow_reversed'].mean().round(3))

    print('\nDistinct assets hit per label (about 5 for attacks):')
    print(df.groupby('label')['asset_id'].nunique())

    print('\nAsset types receiving benign traffic:')
    print(df[df['label'] == 'Benign']['service_type'].value_counts())

    print('\nCriticality mix, attack rows vs benign rows:')
    is_attack = df['label'] != 'Benign'
    print(pd.crosstab(is_attack.rename('is_attack'), df['asset_criticality'], normalize='index').round(3))

    print(f'\nModel input features: {len(get_model_features(df))}')
    print('\nNon-stub rows available for supervised training:')
    print(df[df['reply_stub'] == 0]['label'].value_counts())
    print('\nMulti-packet rows available for the Isolation Forest:')
    print(df[(df['reply_stub'] == 0) & (df['single_packet'] == 0)]['label'].value_counts())


def diagnose(df):
    cols = [c for c in ['fwd_packets_count', 'bwd_packets_count', 'fwd_total_payload_bytes',
                        'bwd_total_payload_bytes', 'duration'] if c in df.columns]
    full = df[df['reply_stub'] == 0]
    print('\nPayload medians by direction_swapped (the groups should agree):')
    for label in ['DoS_HULK', 'Benign']:
        if label in full['label'].values:
            print(label)
            print(full[full['label'] == label].groupby('direction_swapped')[cols].median())

    print('\nTop service ports, to extend PORT_CATEGORIES:')
    print(df['service_port'].value_counts().head(20))


def run_all(with_diagnostics=False):
    df = enrich()
    validate(df)
    if with_diagnostics:
        diagnose(df)
    return df


if __name__ == '__main__':
    run_all(with_diagnostics='--diagnose' in sys.argv)