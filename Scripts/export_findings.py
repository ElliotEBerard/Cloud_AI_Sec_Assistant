import os
import sys
import json
import numpy as np
import pandas as pd
from Enrichment import PARQUET_DIR

EXPORT_DIR = PARQUET_DIR + 'export/'
EPISODES_PATH = PARQUET_DIR + 'episodes.parquet'
ENTITY_PATH = PARQUET_DIR + 'entity_windows.parquet'
ASSETS_PATH = PARQUET_DIR + 'entity_assets.parquet'
PEERS_PATH = PARQUET_DIR + 'peer_links.parquet'
ALERTS_PATH = PARQUET_DIR + 'alert_events.parquet'

MAX_BINS = 120
CONF_MALICIOUS = 0.90

# Simulated responses only; nothing is executed against real resources
ACTIONS = {
    'Bot': ('isolate_resource', 'Isolate this host: it is communicating with a command-and-control server.'),
    'Brute_Force_FTP': ('disable_account', 'Block the source and reset credentials on the targeted FTP accounts.'),
    'Brute_Force_SSH': ('disable_account', 'Block the source and reset credentials on the targeted SSH accounts.'),
    'Web_Attack': ('block_source', 'Block the source and review web application logs for exploitation.'),
    'DoS_HULK': ('block_source', 'Block or rate-limit the source at the network edge.'),
    'DoS_Golden_Eye': ('block_source', 'Block or rate-limit the source at the network edge.'),
    'DoS_Slowloris': ('block_source', 'Block the source and shorten server connection timeouts.'),
    'DDoS_HOIC': ('block_source', 'Block or rate-limit the participating sources.'),
    'DDoS_LOIC_HTTP': ('block_source', 'Block or rate-limit the participating sources.'),
    'Anomaly': ('review_manually', 'Flagged only for unusual behavior; investigate and mark as false positive if benign.'),
}


def jsonable(o):
    if isinstance(o, (pd.Timestamp, np.datetime64)):
        return pd.Timestamp(o).isoformat()
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return None if np.isnan(o) else float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    raise TypeError(f'Cannot serialize {type(o)}')


def dump(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(obj, f, default=jsonable, indent=1)


def records(df):
    return df.astype(object).where(df.notna(), None).to_dict('records')


def timeline(a, start, end):
    secs = max(60, int(np.ceil((end - start).total_seconds() / MAX_BINS / 60)) * 60)
    bins = ((a['timestamp'] - start).dt.total_seconds() // secs).astype(int)
    g = a.groupby(bins).agg(flows=('timestamp', 'size'), malicious=('is_mal', 'sum'))
    pts = [{'t': (start + pd.Timedelta(seconds=int(k) * secs)).isoformat(),
            'flows': int(r.flows), 'malicious': int(r.malicious)} for k, r in g.iterrows()]
    return {'bin_seconds': secs, 'points': pts}


def why(r, link):
    out = []
    if r.alert_class == 'Anomaly':
        out.append('No known attack class matched; flagged only for unusual behavior.')
    else:
        out.append(f'Classified as {r.alert_class} ({r.technique}, {r.tactic}) with mean model confidence {r.evidence:.0%}.')
    if pd.notna(r.anom_share_p90):
        out.append(f'{r.anom_share_p90:.0%} of multi-packet flows scored above the 90th percentile of benign behavior.')
    out.append(f'{r.n_alert_flows:,} sampled flows over {r.duration_min:.0f} minutes from {r.peer}.')
    out.append(f'Target is a {r.service_type} with {r.asset_criticality} criticality.')
    if r.stub_flows:
        out.append(f'{r.stub_flows:,} one-packet replies on the same pair are counted as volume only.')
    if link:
        out.append(f'The source {r.peer} also appears in: {link}.')
    return out


def main():
    ep = pd.read_parquet(EPISODES_PATH).sort_values('start').reset_index(drop=True)
    assets = pd.read_parquet(ASSETS_PATH).set_index('entity')
    peers = pd.read_parquet(PEERS_PATH)
    roll = pd.read_parquet(ENTITY_PATH)
    alerts = pd.read_parquet(ALERTS_PATH, columns=['timestamp', 'episode_id', 'severity'])
    alerts = alerts[alerts['episode_id'].notna()].copy()
    alerts['episode_id'] = alerts['episode_id'].astype(int)
    alerts['is_mal'] = alerts['severity'] == 'malicious'
    by_ep = {k: g for k, g in alerts.groupby('episode_id')}

    ep['finding_id'] = [f'F{i + 1:03d}' for i in range(len(ep))]
    links = dict(zip(peers['peer'], peers['classes']))

    findings = []
    for r in ep.itertuples():
        sev = 'malicious' if r.confidence >= CONF_MALICIOUS else 'suspicious'
        action, detail = ACTIONS.get(r.alert_class, ACTIONS['Anomaly'])
        if sev == 'suspicious' and action != 'review_manually':
            detail = f'Low confidence, review before acting. If confirmed: {detail}'
            action = 'review_manually'
        f = {'finding_id': r.finding_id, 'entity': r.entity, 'peer': r.peer, 'alert_class': r.alert_class,
             'technique': r.technique, 'tactic': r.tactic, 'start': r.start, 'end': r.end,
             'duration_min': round(r.duration_min, 1), 'n_alert_flows': int(r.n_alert_flows),
             'stub_flows': int(r.stub_flows), 'confidence': round(float(r.confidence), 3),
             'severity': sev, 'recommended_action': action, 'action_detail': detail,
             'why': why(r, links.get(r.peer)), 'summary': r.summary, 'status': 'open',
             'window_start': r.window_start}
        findings.append(f)
        detail_doc = dict(f)
        detail_doc['asset'] = {'service_type': r.service_type, 'criticality': r.asset_criticality,
                               'services': assets.loc[r.entity, 'services'],
                               'user_id': r.user_id, 'user_role': r.user_role}
        detail_doc['timeline'] = timeline(by_ep[r.episode_id], r.start, r.end)
        # Ground truth, for your evaluation only. It is not something an analyst would see.
        detail_doc['eval'] = {'purity': round(float(r.purity), 3)}
        dump(detail_doc, f'{EXPORT_DIR}findings/{r.finding_id}.json')

    ids = ep.groupby(['entity', 'window_start'])['finding_id'].agg(list)
    ent = roll.copy()
    ent['finding_ids'] = [ids.get((e, w), []) for e, w in zip(ent['entity'], ent['window_start'])]
    ent['status'] = 'open'
    ent = ent.sort_values('risk_score', ascending=False)

    top = ent.head(3)
    summary = {'window_start': ent['window_start'].min(), 'window_end': ent['window_end'].max(),
               'n_findings': len(findings), 'n_entities': int(ent['entity'].nunique()),
               'n_alert_flows': int(ep['n_alert_flows'].sum()),
               'n_malicious': sum(f['severity'] == 'malicious' for f in findings),
               'headline': list(top['summary']),
               'top_entities': records(top[['entity', 'service_type', 'asset_criticality', 'risk_score',
                                            'tactic_chain', 'campaign_chain', 'n_peers']]),
               'note': 'Counts are sampled flows (capped per attack class), not real traffic volumes.'}

    dump(findings, EXPORT_DIR + 'findings.json')
    dump(records(ent), EXPORT_DIR + 'entities.json')
    dump(records(peers), EXPORT_DIR + 'peers.json')
    dump(summary, EXPORT_DIR + 'summary.json')

    size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(EXPORT_DIR) for f in fs)
    print(f'Wrote {len(findings)} findings, {len(ent)} entity windows, {len(peers)} peer links to {EXPORT_DIR}')
    print(f'Total export size: {size / 1e6:.2f} MB')
    print('\nFindings by severity and recommended action:')
    print(pd.DataFrame(findings).groupby(['severity', 'recommended_action']).size())
    print('\nSample finding:')
    print(json.dumps(json.loads(json.dumps(findings[0], default=jsonable)), indent=1)[:1800])


if __name__ == '__main__':
    main()