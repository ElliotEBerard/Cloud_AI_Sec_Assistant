import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

import boto3

EXPORT_DIR = Path('C:/parquets/export')

# Table name -> (export file, key attributes)
TABLES = {
    'findings': ('findings.json', ['finding_id']),
    'entities': ('entities.json', ['entity', 'window_start']),
    'peers':    ('peers.json',    ['peer']),
}
GSI_CHECK = {'findings': ('entity-start-index', 'entity')}   # table -> (index name, partition key)
EXPECTED = {'findings': 42, 'entities': 13, 'peers': 11}


def to_dynamo(item):
    # DynamoDB rejects Python floats, so round-trip through JSON and parse floats as Decimal
    return json.loads(json.dumps(item), parse_float=Decimal)


def check_keys(name, items, keys):
    for it in items:
        for k in keys:
            v = it.get(k)
            if v is None or v == '':
                raise ValueError(f'{name}: item missing key {k!r}: {str(it)[:120]}')
            if not isinstance(v, str):
                raise ValueError(f'{name}: key {k!r} must be a string, got {type(v).__name__}')
    ids = [tuple(it[k] for k in keys) for it in items]
    if len(ids) != len(set(ids)):
        raise ValueError(f'{name}: duplicate keys in export')


def load_table(ddb, name, filename, keys, dry_run):
    items = [to_dynamo(i) for i in json.load(open(EXPORT_DIR / filename))]
    check_keys(name, items, keys)
    print(f'{name}: {len(items)} items read, keys OK')
    if dry_run:
        return len(items)
    table = ddb.Table(name)
    with table.batch_writer() as batch:       # batches of 25, retries unprocessed items
        for it in items:
            batch.put_item(Item=it)
    return len(items)


def verify(ddb, name, written):
    table = ddb.Table(name)
    count = table.scan(Select='COUNT')['Count']   # fine at this size; a scan pages at 1 MB
    status = 'OK' if count == written else 'MISMATCH'
    print(f'{name}: table holds {count}, wrote {written} [{status}]')
    if name in GSI_CHECK:
        index, pk = GSI_CHECK[name]
        sample = table.scan(Limit=1)['Items'][0][pk]
        res = table.query(IndexName=index,
                          KeyConditionExpression=boto3.dynamodb.conditions.Key(pk).eq(sample))
        print(f'{name}: GSI {index} returned {res["Count"]} item(s) for {pk}={sample}')


def upload_details(s3, bucket, prefix, dry_run):
    files = sorted((EXPORT_DIR / 'findings').glob('F*.json'))
    for f in files:
        doc = json.load(open(f))
        doc.pop('eval', None)                     # ground truth stays out of anything served
        body = json.dumps(doc).encode()
        if not dry_run:
            s3.put_object(Bucket=bucket, Key=f'{prefix}{f.name}', Body=body,
                          ContentType='application/json', ServerSideEncryption='AES256')
    print(f'S3: {len(files)} detail files {"checked" if dry_run else "uploaded"} (eval block removed)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', default=None)
    ap.add_argument('--region', required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--s3-bucket', default=None, help='also upload per-finding detail files')
    ap.add_argument('--s3-prefix', default='findings/')
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    print('Account:', session.client('sts').get_caller_identity()['Account'], '| region:', args.region)
    ddb = session.resource('dynamodb')

    written = {}
    for name, (filename, keys) in TABLES.items():
        written[name] = load_table(ddb, name, filename, keys, args.dry_run)
        if written[name] != EXPECTED[name]:
            print(f'  warning: expected {EXPECTED[name]} items for {name}')

    if args.s3_bucket:
        upload_details(session.client('s3'), args.s3_bucket, args.s3_prefix, args.dry_run)

    if args.dry_run:
        print('\nDry run only, nothing written.')
        return
    print()
    for name in TABLES:
        verify(ddb, name, written[name])


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('FAILED:', e)
        sys.exit(1)