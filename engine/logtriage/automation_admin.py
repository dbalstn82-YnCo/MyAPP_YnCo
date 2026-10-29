"""Offline backup/restore CLI; never expose database passwords in results."""
import argparse
import json
import os
from pathlib import Path
from .safe_backup import snapshot, verify, restore
from .storage import Storage, sqlite_url
from .automation import InstanceLock


def main():
    parser=argparse.ArgumentParser(description='LogTriage backup / restore')
    parser.add_argument('command',choices=('backup','verify','restore'))
    parser.add_argument('--base',type=Path,required=True)
    parser.add_argument('--archive',type=Path)
    parser.add_argument('--db',default=os.environ.get('LOGTRIAGE_DB',''))
    parser.add_argument('--offline-confirmed',action='store_true')
    args=parser.parse_args();base=args.base.resolve()
    if args.command in ('verify','restore') and not args.archive:
        parser.error('--archive required')
    if args.command=='verify':
        result=verify(args.archive)
    elif args.command=='restore':
        result=restore(base,args.archive,args.offline_confirmed,Storage(args.db) if args.db else None)
    else:
        lock=InstanceLock(base/'.automation-worker.lock');lock.acquire()
        try:
            result=snapshot(base,Storage(args.db or sqlite_url(base/'data/logtriage.db')))
        finally:lock.release()
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
