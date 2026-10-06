import os
import sys
import ipaddress
import numpy as np
import pandas as pd

from Enrichment import MITRE_MAP, PORT_CATEGORIES, PARQUET_DIR, USERS_PATH

SCORED_PATH = PARQUET_DIR + 'scored_events.parquet'
ALERTS_PATH = PARQUET_DIR + 'alert_events.parquet'
EPISODES_PATH = PARQUET_DIR + 'episodes.parquet'
ENTITY_PATH = PARQUET_DIR + 'entity_windows.parquet'
ASSETS_PATH = PARQUET_DIR + 'entity_assets.parquet'
PEERS_PATH = PARQUET_DIR + 'peer_links.parquet'

INTERNAL_NET = ipaddress.ip_network('172.31.0.0/16')
GAP_MINUTES = 30
MIN_EPISODE_FLOWS = 3
ANOMALY_MIN_FLOWS = 10      # anomaly-only findings need more flows than classified ones
ABSORB_SHARE = 0.10         # stray classes below this share of an entity/peer pair fold into its main class
VOLUME_FULL_CONF = 30       # bursts smaller than this get proportionally less confidence
CONF_MALICIOUS = 0.90
ANOMALY_ALERT_PCT = 0.99
ANOMALY_WEIGHT = 0.6
SERVER_MIN_SHARE = 0.05     # a service counts only if it is at least 5% of what the host serves
WINDOW_DAYS = 7
SEED = 42

# Optional hand labels for your lab's known servers, e.g. {'172.31.69.25': 'multi_service_server'}
SERVER_OVERRIDES = {}

# TELNET and PROXY are left out on purpose: they receive internet-wide scanning, so they say little
# about what a host is. SMB, NetBIOS, RDP, VNC and RPC count as workstation traffic.
SERVICE_GROUP = {'FTP': 'file_server', 'SSH': 'ssh_server', 'HTTP': 'web_server', 'HTTPS': 'web_server',
                 'HTTP-ALT': 'web_server', 'MSSQL': 'database_server', 'MYSQL': 'database_server',
                 'SMB': 'workstation', 'NETBIOS': 'workstation', 'RDP': 'workstation',
                 'VNC': 'workstation', 'RPC': 'workstation'}

SERVICE_CRIT = {'workstation': 'low', 'web_server': 'medium', 'file_server': 'medium',
                'network_device': 'medium', 'ssh_server': 'high', 'database_server': 'high',
                'multi_service_server': 'high'}
CRIT_RANK = {'low': 1, 'medium': 2, 'high': 3}

CLASS_TACTIC = dict(MITRE_MAP)
CLASS_TACTIC['Web_Attack'] = ('T1190', 'initial_access')
CLASS_TACTIC['Anomaly'] = ('none', 'unknown')

pd.set_option('display.width', 250)
pd.set_option('display.max_columns', None)


def is_internal(series):
    flags = {}
    for ip in series.dropna().unique():
        try:
            flags[ip] = ipaddress.ip_address(ip) in INTERNAL_NET
        except ValueError:
            flags[ip] = False
    return series.map(flags).eq(True)


def attach_entities(df):
    src_in, dst_in = is_internal(df['src_ip']), is_internal(df['dst_ip'])
    df['entity'] = df['dst_ip'].where(dst_in, df['src_ip'].where(src_in))
    df['peer'] = df['src_ip'].where(dst_in, df['dst_ip'].where(src_in))
    # Which end holds the service port (stubs keep their recorded direction)
    dst_known = df['dst_port'].isin(list(PORT_CATEGORIES))
    service_ip = df['dst_ip'].where(dst_known, df['src_ip'])
    df['entity_serves'] = (df['entity'] == service_ip) & (df['port_category'] != 'unknown/ephemeral')
    return df


def build_assets(df):
    served = df[df['entity_serves']]
    counts = served.groupby(['entity', 'port_category']).size()
    share = counts.div(counts.groupby(level='entity').sum(), level='entity').rename('share').reset_index()
    share['service_type'] = share['port_category'].map(SERVICE_GROUP)
    share = share[(share['share'] >= SERVER_MIN_SHARE) & share['service_type'].notna()
                  & (share['service_type'] != 'workstation')]
    kinds = share.groupby('entity')['service_type'].agg(lambda s: sorted(set(s)))

    def classify(entity):
        if entity in SERVER_OVERRIDES:
            return SERVER_OVERRIDES[entity]
        k = kinds.get(entity, [])
        return 'workstation' if not k else (k[0] if len(k) == 1 else 'multi_service_server')

    assets = pd.DataFrame({'entity': np.sort(df['entity'].dropna().unique())})
    assets['service_type'] = assets['entity'].map(classify)
    assets['asset_criticality'] = assets['service_type'].map(SERVICE_CRIT)

    users = pd.read_parquet(USERS_PATH)
    priv = users.loc[users['user_role'].isin(['admin', 'service_account']), 'user_id'].to_numpy()
    std = users.loc[users['user_role'] == 'standard_user', 'user_id'].to_numpy()
    rng = np.random.default_rng(SEED)
    is_ws = (assets['service_type'] == 'workstation').to_numpy()
    assets['user_id'] = np.where(is_ws, rng.choice(std, len(assets)), rng.choice(priv, len(assets)))
    assets['user_role'] = assets['user_id'].map(users.set_index('user_id')['user_role'])
    # The server types each host was seen exposing, so the dashboard can show why it was classified
    assets['services'] = assets['entity'].map(lambda e: ', '.join(kinds.get(e, [])))
    return assets


def flag_alerts(df):
    cls = df['pred_class'].where(df['pred_class'].notna() & (df['pred_class'] != 'Benign'))
    anomaly_only = cls.isna() & (df['anomaly_pct'] >= ANOMALY_ALERT_PCT)
    cls = cls.mask(anomaly_only, 'Anomaly')
    df['alert_class'] = cls
    df['evidence_score'] = np.where(cls == 'Anomaly', ANOMALY_WEIGHT * df['anomaly_pct'], df['attack_prob'])
    return df


def absorb_minor_classes(alerts, min_share=ABSORB_SHARE):
    # Within one entity/peer pair, fold small stray classes into the pair's dominant class.
    # Works over the whole file, not per time window, which suits one lab session per pair.
    keys = ['entity', 'peer']
    n = alerts.groupby(keys + ['alert_class']).size().rename('n').reset_index()
    n['share'] = n['n'] / n.groupby(keys)['n'].transform('sum')
    dom = (n.sort_values('n', ascending=False).drop_duplicates(keys)
             [keys + ['alert_class']].rename(columns={'alert_class': 'dom_class'}))
    n = n.merge(dom, on=keys)
    minor = n[(n['alert_class'] != n['dom_class']) & (n['share'] < min_share)
              & (n['dom_class'] != 'Anomaly')]
    remap = {(r.entity, r.peer, r.alert_class): r.dom_class for r in minor.itertuples()}
    if remap:
        keyed = zip(alerts['entity'], alerts['peer'], alerts['alert_class'])
        alerts['alert_class'] = [remap.get(k, k[2]) for k in keyed]
    print(f'Absorbed {len(remap)} minor class(es) into the dominant class of their entity/peer pair')
    return alerts


def episode_text(r):
    span = f"{r.start:%b %d %H:%M} to {r.end:%b %d %H:%M}"
    base = (f"{r.entity} ({r.service_type}, {r.asset_criticality} criticality) had "
            f"{r.n_alert_flows:,} flagged flows with {r.peer} from {span}. ")
    if r.alert_class == 'Anomaly':
        what = "No known attack class matched; the flows were flagged only for unusual behavior. "
    else:
        what = f"Classified as {r.alert_class} ({r.technique}, {r.tactic}). "
    anom = (f"{r.anom_share_p90:.0%} of multi-packet flows scored above the 90th percentile "
            f"of benign behavior. ") if pd.notna(r.anom_share_p90) else ''
    stub = (f"{r.stub_flows:,} one-packet replies on the same pair are counted as volume only."
            if r.stub_flows else '')
    return (base + what + anom + stub).strip()


def build_episodes(alerts, df, assets):
    keys = ['entity', 'peer', 'alert_class']
    alerts = alerts.sort_values(keys + ['timestamp']).copy()
    gap = alerts['timestamp'] - alerts.groupby(keys, sort=False)['timestamp'].shift()
    alerts['episode_id'] = (gap.isna() | (gap > pd.Timedelta(minutes=GAP_MINUTES))).cumsum()

    alerts['severity'] = np.where((alerts['alert_class'] != 'Anomaly') & (alerts['pred_conf'] >= CONF_MALICIOUS),
                                  'malicious', 'suspicious')
    alerts['is_attack'] = alerts['label'] != 'Benign'
    alerts['has_anom'] = alerts['anomaly_pct'].notna()
    alerts['hi_anom'] = alerts['anomaly_pct'] >= 0.9
    alerts['is_mal'] = alerts['severity'] == 'malicious'

    ep = alerts.groupby('episode_id').agg(
        entity=('entity', 'first'), peer=('peer', 'first'), alert_class=('alert_class', 'first'),
        start=('timestamp', 'min'), end=('timestamp', 'max'), n_alert_flows=('timestamp', 'size'),
        evidence=('evidence_score', 'mean'), n_malicious=('is_mal', 'sum'),
        n_true_attack=('is_attack', 'sum'), anom_n=('has_anom', 'sum'), anom_hi=('hi_anom', 'sum'),
    ).reset_index()
    need = np.where(ep['alert_class'] == 'Anomaly', ANOMALY_MIN_FLOWS, MIN_EPISODE_FLOWS)
    ep = ep[ep['n_alert_flows'] >= need].reset_index(drop=True)

    ep['purity'] = ep['n_true_attack'] / ep['n_alert_flows']
    # Small bursts earn proportionally less confidence, whatever the host
    ep['confidence'] = ep['evidence'] * np.minimum(1.0, ep['n_alert_flows'] / VOLUME_FULL_CONF)
    ep['anom_share_p90'] = np.where(ep['anom_n'] > 0, ep['anom_hi'] / ep['anom_n'].clip(lower=1), np.nan)
    ep['technique'] = ep['alert_class'].map(lambda c: CLASS_TACTIC.get(c, ('none', 'unknown'))[0])
    ep['tactic'] = ep['alert_class'].map(lambda c: CLASS_TACTIC.get(c, ('none', 'unknown'))[1])
    ep['duration_min'] = (ep['end'] - ep['start']).dt.total_seconds() / 60

    # Count unscored reply stubs on the same entity/peer pair during each episode
    stubs = df.loc[df['reply_stub'] == 1, ['entity', 'peer', 'timestamp']].sort_values('timestamp')
    m = pd.merge_asof(stubs, ep[['episode_id', 'entity', 'peer', 'start', 'end']].sort_values('start'),
                      left_on='timestamp', right_on='start', by=['entity', 'peer'], direction='backward')
    m = m[m['end'].notna() & (m['timestamp'] <= m['end'])]
    ep['stub_flows'] = ep['episode_id'].map(m.groupby('episode_id').size()).fillna(0).astype(int)

    ep = ep.merge(assets[['entity', 'service_type', 'asset_criticality', 'user_id', 'user_role']],
                  on='entity', how='left')
    ep['summary'] = ep.apply(episode_text, axis=1)

    alerts['episode_id'] = alerts['episode_id'].where(alerts['episode_id'].isin(ep['episode_id'])).astype('Int64')
    return ep, alerts


def rollup(ep):
    rows = []
    for entity, g in ep.groupby('entity'):
        g = g.sort_values('start')
        tactics = [t for t in dict.fromkeys(g['tactic']) if t != 'unknown'] or ['unknown']
        known = [t for t in tactics if t != 'unknown']
        top = g.loc[g['n_alert_flows'].idxmax()]
        sev = float(g['confidence'].max())
        vol = min(1.0, np.log10(1 + g['n_alert_flows'].sum()) / 4)
        chain = min(1.0, max(0, len(known) - 1) / 3)
        crit = CRIT_RANK[top['asset_criticality']] / 3
        risk = 100 * (0.40 * sev + 0.20 * vol + 0.20 * chain + 0.20 * crit)
        chain_txt = ' -> '.join(tactics)
        campaign_txt = ' -> '.join(dict.fromkeys(g['alert_class']))
        summary = (f"{entity} ({top['service_type']}, {top['asset_criticality']} criticality) has {len(g)} "
                   f"episode(s) from {g['peer'].nunique()} peer(s), {int(g['n_alert_flows'].sum()):,} flagged flows. "
                   + (f"Tactic sequence: {chain_txt}. " if len(known) > 1 else f"Tactic: {chain_txt}. ")
                   + f"Largest: {top['alert_class']} from {top['peer']} ({int(top['n_alert_flows']):,} flows).")
        summary += f" Campaign order: {campaign_txt}."
        rows.append({'entity': entity, 'service_type': top['service_type'],
                     'asset_criticality': top['asset_criticality'], 'user_id': top['user_id'],
                     'user_role': top['user_role'], 'n_episodes': len(g),
                     'n_alert_flows': int(g['n_alert_flows'].sum()), 'n_peers': g['peer'].nunique(),
                     'tactic_chain': chain_txt, 'campaign_chain': campaign_txt,
                     'top_class': top['alert_class'], 'top_peer': top['peer'],
                     'top_technique': top['technique'],
                     'severity': 'malicious' if sev >= CONF_MALICIOUS else 'suspicious',
                     'risk_score': round(risk, 1), 'risk_evidence': round(sev, 3),
                     'risk_volume': round(vol, 3), 'risk_chain': round(chain, 3), 'risk_criticality': round(crit, 3),
                     'first_seen': g['start'].min(), 'last_seen': g['end'].max(), 'summary': summary})
    return pd.DataFrame(rows)


def peer_links(ep):
    p = ep.groupby('peer').agg(n_entities=('entity', 'nunique'),
                               classes=('alert_class', lambda s: ', '.join(sorted(set(s)))),
                               n_flows=('n_alert_flows', 'sum'),
                               first_seen=('start', 'min'), last_seen=('end', 'max')).reset_index()
    return p[(p['n_entities'] >= 2) | p['classes'].str.contains(',')].sort_values('n_flows', ascending=False)


def evaluate(df, ep):
    scorable = df[df['reply_stub'] == 0]
    print('\nShare of scorable flows inside a finding, by true label (benign row = false-alarm rate):')
    print(scorable['episode_id'].notna().groupby(scorable['label']).mean().round(3))
    print(f"\nFindings: {len(ep)} | median purity {ep['purity'].median():.3f} | "
          f"findings with purity < 0.5: {(ep['purity'] < 0.5).sum()}")
    print('\nFindings by alert class:')
    print(ep.groupby('alert_class').agg(findings=('episode_id', 'size'), flows=('n_alert_flows', 'sum'),
                                        mean_purity=('purity', 'mean')).round(3))
    low = ep[ep['purity'] < 0.5]
    if len(low):
        print('\nFindings with purity < 0.5:')
        print(low[['entity', 'peer', 'alert_class', 'n_alert_flows', 'purity', 'confidence', 'start']]
              .to_string(index=False))
    print('\nSmallest findings:')
    print(ep.sort_values('n_alert_flows').head(6)
            [['entity', 'peer', 'alert_class', 'n_alert_flows', 'purity', 'confidence']].to_string(index=False))


def main():
    df = pd.read_parquet(SCORED_PATH)
    df = attach_entities(df)
    print(f'Rows: {len(df)} | with no internal endpoint (dropped): {df["entity"].isna().sum()}')
    df = df[df['entity'].notna()].copy()

    assets = build_assets(df)
    print(f'\nInternal assets: {len(assets)}')
    print(assets['service_type'].value_counts())
    print('\nMulti-service servers and the services they were seen exposing:')
    print(assets[assets['service_type'] == 'multi_service_server'][['entity', 'services']].to_string(index=False))

    df = flag_alerts(df)
    alerts = df[df['alert_class'].notna()].copy()
    alerts = absorb_minor_classes(alerts)
    print(f'\nAlert flows: {len(alerts)}')
    ep, alerts = build_episodes(alerts, df, assets)
    df['episode_id'] = alerts['episode_id']

    t0 = alerts['timestamp'].min().normalize()
    ep['window_start'] = t0 + pd.to_timedelta(((ep['start'] - t0).dt.days // WINDOW_DAYS) * WINDOW_DAYS, unit='D')
    roll = pd.concat([rollup(g).assign(window_start=w) for w, g in ep.groupby('window_start')], ignore_index=True)
    roll['window_end'] = roll['window_start'] + pd.Timedelta(days=WINDOW_DAYS)
    peers = peer_links(ep)

    evaluate(df, ep)
    print('\nLargest findings:')
    print(ep.sort_values('n_alert_flows', ascending=False).head(15)
            [['entity', 'peer', 'alert_class', 'start', 'end', 'n_alert_flows', 'stub_flows', 'purity']]
            .to_string(index=False))
    print('\nHighest-risk entity windows:')
    print(roll.sort_values('risk_score', ascending=False).head(12)
              [['window_start', 'entity', 'service_type', 'asset_criticality', 'severity',
                'risk_score', 'tactic_chain', 'n_peers']].to_string(index=False))
    top_entity = roll.sort_values('risk_score', ascending=False).iloc[0]['entity']
    print(f'\nTimeline of {top_entity}:')
    print(ep[ep['entity'] == top_entity].sort_values('start')
            [['start', 'end', 'peer', 'alert_class', 'tactic', 'n_alert_flows']].to_string(index=False))
    print('\nPeers linked across campaigns or victims:')
    print(peers.head(15).to_string(index=False))
    print('\nSample narratives:')
    for text in roll.sort_values('risk_score', ascending=False)['summary'].head(3):
        print(' -', text)
    for text in ep.sort_values('n_alert_flows', ascending=False)['summary'].head(2):
        print(' -', text)

    os.makedirs(PARQUET_DIR, exist_ok=True)
    assets.to_parquet(ASSETS_PATH, index=False)
    ep.to_parquet(EPISODES_PATH, index=False)
    roll.to_parquet(ENTITY_PATH, index=False)
    peers.to_parquet(PEERS_PATH, index=False)
    alerts[['flow_id', 'timestamp', 'entity', 'peer', 'alert_class', 'severity', 'evidence_score',
            'pred_conf', 'anomaly_pct', 'label', 'episode_id', 'single_packet']].to_parquet(ALERTS_PATH, index=False)
    print('\nSaved assets, episodes, entity windows, peer links and alert events.')


if __name__ == '__main__':
    main()