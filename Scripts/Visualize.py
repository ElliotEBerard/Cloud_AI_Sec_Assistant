# find unnecessary columns based on data
import pandas as pd
import numpy as np

'''def count_labels(parquet_path):
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

#analyze_combined_columns('./Datasets/base_data.parquet')

import pandas as pd

def check_dst_ports(parquet_path):
    df = pd.read_parquet(parquet_path, columns=['dst_port', 'label'])
    
    # Common well-known ports and their typical service
    well_known_ports = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
        110: 'POP3', 123: 'NTP', 137: 'NETBIOS', 138: 'NETBIOS', 139: 'NETBIOS',
        143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 587: 'SMTP-SUB', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'ORACLE', 3306: 'MYSQL', 3389: 'RDP',
        5432: 'POSTGRESQL', 5900: 'VNC', 6379: 'REDIS', 8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT', 27017: 'MONGODB'
    }
    
    unique_ports = sorted(df['dst_port'].unique())
    print(f"Total unique dst_ports in file: {len(unique_ports)}\n")
    
    # Which well-known ports actually appear
    found_well_known = {p: well_known_ports[p] for p in unique_ports if p in well_known_ports}
    print("=" * 50)
    print("WELL-KNOWN PORTS FOUND IN DATA")
    print("=" * 50)
    for port, service in sorted(found_well_known.items()):
        count = (df['dst_port'] == port).sum()
        pct = round(count / len(df) * 100, 3)
        print(f"  Port {port} ({service}): {count} rows ({pct}%)")
    
    # Top 20 most frequent ports overall (well-known or not)
    print("\n" + "=" * 50)
    print("TOP 20 MOST FREQUENT DST_PORTS (any port)")
    print("=" * 50)
    top_ports = df['dst_port'].value_counts().head(20)
    for port, count in top_ports.items():
        service = well_known_ports.get(port, 'unknown/ephemeral')
        pct = round(count / len(df) * 100, 3)
        print(f"  Port {port} ({service}): {count} rows ({pct}%)")
    
    # Cross-tab: port usage by label, for context
    print("\n" + "=" * 50)
    print("DST_PORT BY LABEL (top 3 ports per label)")
    print("=" * 50)
    for label in df['label'].unique():
        subset = df[df['label'] == label]
        top3 = subset['dst_port'].value_counts().head(3)
        print(f"\n{label}:")
        for port, count in top3.items():
            service = well_known_ports.get(port, 'unknown/ephemeral')
            print(f"    Port {port} ({service}): {count}")
    
    return found_well_known, top_ports

found, top = check_dst_ports('./Datasets/base_data_reduced.parquet')

df = pd.read_parquet('./Datasets/base_data_enriched.parquet')
cols = [c for c in ['fwd_packets_count', 'bwd_packets_count', 'fwd_total_payload_bytes',
                    'bwd_total_payload_bytes', 'duration'] if c in df.columns]
full = df[df['reply_stub'] == 0]

print(full.groupby('label')['flow_reversed'].mean().round(3))
print(full[full['label'] == 'Benign'].groupby('flow_reversed')[cols].median())
print(full[full['label'].isin(['DoS_HULK', 'DoS_Golden_Eye', 'DDoS_LOIC_HTTP'])]
      .groupby(['label', 'flow_reversed'])[cols].median())

print(df[df['reply_stub'] == 0]['label'].value_counts())

import numpy as np
import pandas as pd
from Enrichment import ENRICHED_PATH

df = pd.read_parquet(ENRICHED_PATH)
sl = df[(df['label'] == 'DoS_Slowloris') & (df['reply_stub'] == 0)].copy()
sl['phase'] = np.where(sl['timestamp'] >= '2018-02-15 10:40:40', 'last_80s', 'earlier')
cols = [c for c in ['duration', 'fwd_packets_count', 'bwd_packets_count', 'bytes_rate',
                    'handshake_complete', 'rst_flag_counts', 'fin_flag_counts'] if c in sl.columns]
print(sl.groupby('phase')[cols].median())
print(sl['phase'].value_counts())

import pandas as pd
from Enrichment import ENRICHED_PATH

df = pd.read_parquet(ENRICHED_PATH)
total_pkts = df['fwd_packets_count'] + df['bwd_packets_count']
df['single_packet'] = (total_pkts <= 1).astype(int)

summary = pd.DataFrame({
    'rows': df.groupby('label').size(),
    'single_packet_share': df.groupby('label')['single_packet'].mean().round(3),
    'stub_share': df.groupby('label')['reply_stub'].mean().round(3),
})
print(summary)
print('\nSingle-packet, forward-only (not caught by reply_stub):')
print(df[(df['single_packet'] == 1) & (df['reply_stub'] == 0)].groupby('label').size())

import pandas as pd
from Enrichment import ENRICHED_PATH

df = pd.read_parquet(ENRICHED_PATH, columns=['label', 'src_ip', 'dst_ip'])
for label, g in df[df['label'] != 'Benign'].groupby('label'):
    print(label)
    print('  top src:', g['src_ip'].value_counts().head(3).to_dict())
    print('  top dst:', g['dst_ip'].value_counts().head(3).to_dict())
b = df[df['label'] == 'Benign']
print('\nBenign unique src_ip:', b['src_ip'].nunique(), '| unique dst_ip:', b['dst_ip'].nunique())


df = pd.read_parquet(ENRICHED_PATH)
sl = df[(df['label'] == 'DoS_Slowloris') & (df['reply_stub'] == 0)]
tail = sl[sl['timestamp'] >= '2018-02-15 10:40:40']
print(tail['single_packet'].value_counts())
print(tail[tail['single_packet'] == 0][['fwd_packets_count', 'bwd_packets_count', 'duration']].describe())

import pandas as pd
df = pd.read_parquet('C:/parquets/scored_events.parquet')
sl = df[(df['label'] == 'DoS_Slowloris') & (df['fold'] >= 0) & (df['pred_class'] != df['target'])]
print(sl.groupby(['fold', 'evidence']).size())'''

import pandas as pd

enr = pd.read_parquet('C:/parquets/base_data_enriched.parquet')
sc = pd.read_parquet('C:/parquets/scored_events.parquet')
assert (enr['flow_id'].to_numpy() == sc['flow_id'].to_numpy()).all()

sl = sc[(sc['label'] == 'DoS_Slowloris') & (sc['fold'] >= 0)].copy()
sl['missed'] = sl['pred_class'] != sl['target']
cols = [c for c in ['duration', 'fwd_packets_count', 'bwd_packets_count', 'bytes_rate',
                    'handshake_complete', 'rst_flag_counts', 'fin_flag_counts'] if c in enr.columns]
for c in cols:
    sl[c] = enr.loc[sl.index, c].to_numpy()

print(sl.groupby(['fold', 'missed']).size().unstack(fill_value=0))
print(sl[sl['fold'].isin([0, 3]) & (sl['evidence'] == 'multi_packet')]
        .groupby(['fold', 'missed'])[cols].median())
print(sl[sl['missed']].groupby(['fold', 'pred_class']).size())
print(sl.groupby('fold')['timestamp'].agg(['min', 'max']))