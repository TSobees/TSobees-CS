import argparse
import csv
import json
from pathlib import Path
from .parser import parse_scan, inventory, markdown

def main(argv=None):
    p=argparse.ArgumentParser(description='Summarize an existing Nmap XML file offline.')
    p.add_argument('xml',nargs='?',type=Path,default=Path(__file__).resolve().parents[1]/'data/scans/network_scan.xml')
    p.add_argument('--output-dir',type=Path,default=Path('outputs'))
    a=p.parse_args(argv)
    try: report=parse_scan(a.xml)
    except (OSError,ValueError) as error: p.error(str(error))
    a.output_dir.mkdir(parents=True,exist_ok=True)
    (a.output_dir/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (a.output_dir/'inventory.md').write_text(markdown(report),encoding='utf-8')
    with (a.output_dir/'inventory.csv').open('w',newline='',encoding='utf-8') as stream:
        fields=['address','host_state','port','protocol','state','service','product','version']
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for row in inventory(report):
            writer.writerow({k:("'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v) for k,v in row.items()})
    print(json.dumps(report['summary']));print('Reports: '+str(a.output_dir.resolve()))
    return 0

if __name__=='__main__': raise SystemExit(main())
