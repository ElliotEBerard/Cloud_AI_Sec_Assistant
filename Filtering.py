import re
import sys
import numpy as np
import pandas as pd

RAW_DIR = './Datasets/Raw_Data/'
CLEAN_DIR = './Datasets/Clean_Data/'
BASE_PATH = './Datasets/base_data.parquet'
NORMALIZED_PATH = './Datasets/base_data_normalized.parquet'
REDUCED_PATH = './Datasets/base_data_reduced.parquet'
EXT = '.csv'
CAP = 25000
SEED = 42

ALL_FILES = ['benign', 'BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot', 'DoS_Golden_Eye', 'dos_hulk',
             'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection',
             'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4',
             'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11',
             'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'hoic_2']

BAD_COLS = ['delta_start', 'handshake_duration']

# Identifiers stay in the file (the hunting layer correlates on them) and are excluded from model inputs
ID_COLUMNS = ['flow_id', 'src_ip', 'src_port', 'dst_ip']
# Needed downstream, so never dropped by the correlation step
PROTECTED_COLUMNS = ['timestamp', 'dst_port', 'handshake_duration', 'label',
                     'fwd_packets_count', 'direction_swapped']

# Keep in sync with the keys of PORT_CATEGORIES in Enrichement.py
SERVICE_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 1433, 3128, 3306, 3389, 5900, 8080]
# None = normalize every reversed full flow; ['DoS_HULK'] = conservative version
SWAP_ONLY_LABELS = None
# Pairs that the fwd<->bwd name rule can't find
EXTRA_PAIRS = [('src_ip', 'dst_ip'), ('src_port', 'dst_port'),
               ('avg_fwd_packets_per_bulk', 'avg_bwd_packets_bulk_rate')]


def clean_data():
    for name in ALL_FILES:
        reader = pd.read_csv(RAW_DIR + name + EXT, header=0, encoding='utf-8',
                             low_memory=False, chunksize=50000)
        first_chunk = True
        for chunk in reader:
            for col in BAD_COLS:
                if col in chunk.columns:
                    chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
            chunk.to_csv(CLEAN_DIR + name + EXT, mode='w' if first_chunk else 'a',
                         header=first_chunk, index=False)
            first_chunk = False
        print(f'{name} cleaned')


def combine_files():
    # Split files pool under one label (dos_hulk_2 -> dos_hulk); benign files stay capped individually
    groups = {}
    for name in ALL_FILES:
        base = re.sub(r'_\d+$', '', name)
        if base == 'benign':
            base = name
        groups.setdefault(base, []).append(name)

    sampled = {}
    for base, parts in groups.items():
        dfs = []
        for name in parts:
            df = pd.read_csv(CLEAN_DIR + name + EXT, header=0, encoding='utf-8')
            dfs.append(df.drop_duplicates())
            print(f'{name} processed')
        df = dfs[0] if len(dfs) == 1 else pd.concat(dfs, ignore_index=True).drop_duplicates()
        del dfs
        if len(df) > CAP:
            df = df.sample(n=CAP, random_state=SEED)
        sampled[base] = df
        print(f'{base}: {len(df)} rows')

    combined = pd.concat(sampled, ignore_index=True)
    mixed = combined.sample(frac=1, random_state=SEED).reset_index(drop=True)
    mixed.to_parquet(BASE_PATH, index=False)
    print(f'Wrote {BASE_PATH}: {len(mixed)} rows')


def direction_pairs(columns):
    # fwd_x <-> bwd_x, including names where the tokens sit in the middle or appear twice
    cols = set(columns)
    pairs, unpaired, seen = [], [], set()
    for c in columns:
        if 'fwd' not in c and 'bwd' not in c:
            continue
        partner = re.sub(r'fwd|bwd', lambda m: 'bwd' if m.group() == 'fwd' else 'fwd', c)
        if partner not in cols:
            unpaired.append(c)
        elif c not in seen:
            pairs.append((c, partner))
            seen.update([c, partner])
    return pairs, unpaired


def fix_down_up_rate(df, swap):
    # down_up_rate is a ratio, so swapping its inputs is not enough: recompute it for swapped rows
    if 'down_up_rate' not in df.columns or not swap.any():
        return
    ok = ~swap & (df['fwd_packets_count'].to_numpy() > 0)
    ref = df[ok].head(100000)
    candidates = {
        'packets': lambda d: d['bwd_packets_count'] / d['fwd_packets_count'],
        'payload': lambda d: d['bwd_total_payload_bytes'] / d['fwd_total_payload_bytes'].where(
            d['fwd_total_payload_bytes'] > 0),
    }
    scores = {n: ref['down_up_rate'].corr(f(ref).fillna(0)) for n, f in candidates.items()}
    print('down_up_rate correlation with candidate formulas:', scores)
    name = max(scores, key=lambda n: scores[n] if pd.notna(scores[n]) else -1)
    if pd.isna(scores[name]) or scores[name] < 0.95:
        print('down_up_rate formula not recognized; swapped rows were left unchanged')
        return
    new = candidates[name](df).replace([np.inf, -np.inf], np.nan).fillna(0)
    if (ref['down_up_rate'] % 1 == 0).all():
        new = np.floor(new)
    df.loc[swap, 'down_up_rate'] = new[swap].to_numpy()


def normalize_direction():
    # Make dst_port the service side and fwd_* the client side for flows that were recorded reversed.
    # One-packet reply stubs (0 forward packets) are left alone so reply_stub stays identifiable.
    df = pd.read_parquet(BASE_PATH)
    dst = df['dst_port'].to_numpy()
    src = df['src_port'].to_numpy()
    reversed_flow = ~np.isin(dst, SERVICE_PORTS) & np.isin(src, SERVICE_PORTS)
    stub = df['fwd_packets_count'].to_numpy() == 0
    swap = reversed_flow & ~stub
    if SWAP_ONLY_LABELS:
        swap &= df['label'].isin(SWAP_ONLY_LABELS).to_numpy()

    pairs, unpaired = direction_pairs(df.columns)
    extra = [p for p in EXTRA_PAIRS if p[0] in df.columns and p[1] in df.columns]
    in_extra = {c for p in extra for c in p}
    unpaired = [c for c in unpaired if c not in in_extra]
    pairs += extra

    for a, b in pairs:
        a_vals, b_vals = df[a].to_numpy(), df[b].to_numpy()
        df[a] = np.where(swap, b_vals, a_vals)
        df[b] = np.where(swap, a_vals, b_vals)

    fix_down_up_rate(df, swap)
    df['direction_swapped'] = swap.astype(int)

    print(f'Swapped {swap.sum()} rows across {len(pairs)} column pairs')
    print('Direction columns with no partner (left as-is):', unpaired)
    print('\nRows swapped, by label:')
    print(df.groupby('label')['direction_swapped'].sum()[lambda s: s > 0])
    chk = df[(df['label'] == 'DoS_HULK') & ~stub]
    print('\nDoS_HULK payload medians (should now match across groups):')
    print(chk.groupby('direction_swapped')[['fwd_total_payload_bytes', 'bwd_total_payload_bytes']].median())

    df.to_parquet(NORMALIZED_PATH, index=False)
    print(f'Wrote {NORMALIZED_PATH}')


def get_necessary_columns(df, corr_threshold=0.999):
    skip = set(ID_COLUMNS) | {'direction_swapped'}
    numeric_cols = [c for c in df.select_dtypes(include=[np.number]).columns if c not in skip]
    drop_set = set()

    # Mathematically redundant: variance = std^2, flag percentages = count / total
    drop_set.update(c for c in df.columns if 'variance' in c.lower())
    drop_set.update(c for c in df.columns if 'percentage' in c.lower())

    # Zero-variance columns
    nunique = df.nunique()
    drop_set.update(nunique[nunique <= 1].index.tolist())

    # Near-exact correlation clusters, collapsed with union-find
    remaining = [c for c in numeric_cols if c not in drop_set]
    corr = df[remaining].corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))

    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for col in upper.columns:
        for row in upper.index:
            val = upper.loc[row, col]
            if pd.notna(val) and val >= corr_threshold:
                union(row, col)

    clusters = {}
    for col in parent:
        clusters.setdefault(find(col), []).append(col)
    for members in clusters.values():
        if len(members) > 1:
            keep = min(members, key=len)
            drop_set.update(c for c in members if c != keep)

    drop_set -= set(ID_COLUMNS) | set(PROTECTED_COLUMNS)
    necessary = [c for c in df.columns if c not in drop_set]
    print(f'Total columns: {len(df.columns)} | Dropped: {len(drop_set)} | Kept: {len(necessary)}')
    return necessary


def reduce_columns():
    df = pd.read_parquet(NORMALIZED_PATH)
    columns = get_necessary_columns(df)
    required = ID_COLUMNS + PROTECTED_COLUMNS
    missing = [c for c in required if c not in columns]
    assert not missing, f'Required columns were dropped: {missing}'
    df[columns].to_parquet(REDUCED_PATH, index=False)
    print(f'Wrote {REDUCED_PATH}')


if __name__ == '__main__':
    # python filtering.py                 combine + normalize direction + reduce
    # python filtering.py --clean         clean + combine + normalize + reduce
    # python filtering.py --reduce-only   normalize + reduce from the existing base_data.parquet
    args = sys.argv[1:]
    if '--reduce-only' not in args:
        if '--clean' in args:
            clean_data()
        combine_files()
    normalize_direction()
    reduce_columns()