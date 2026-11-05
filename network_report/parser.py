"""Read recorded Nmap XML without invoking Nmap or contacting hosts."""
from pathlib import Path
import xml.etree.ElementTree as ET

def parse_scan(path):
    content=Path(path).read_bytes()
    if len(content)>20*1024*1024:
        raise ValueError('XML input exceeds the 20 MB limit.')
    if b'<!ENTITY' in content.upper() or b'<!DOCTYPE' in content.upper() and b'[' in content.split(b'>',2)[0]:
        raise ValueError('XML entity declarations are not supported.')
    try: root=ET.fromstring(content)
    except ET.ParseError as error: raise ValueError('Invalid Nmap XML: '+str(error)) from error
    if root.tag!='nmaprun': raise ValueError('Expected an nmaprun XML document.')
    hosts=[]
    for host in root.findall('host'):
        address=next((a.get('addr','') for a in host.findall('address') if a.get('addrtype') in ['ipv4','ipv6']), '')
        if not address: continue
        status=host.find('status');ports=[]
        for port in host.findall('./ports/port'):
            state=port.find('state');service=port.find('service')
            ports.append({'port':int(port.get('portid','0')),'protocol':port.get('protocol',''),
                'state':state.get('state','unknown') if state is not None else 'unknown',
                'service':service.get('name','') if service is not None else '',
                'product':service.get('product','') if service is not None else '',
                'version':service.get('version','') if service is not None else '',
                'scripts':[{'id':s.get('id',''),'output':s.get('output','')} for s in port.findall('script')]})
        hosts.append({'address':address,'status':status.get('state','unknown') if status is not None else 'unknown',
            'hostnames':[h.get('name','') for h in host.findall('./hostnames/hostname')],
            'ports':ports,'other_port_states':[dict(p.attrib) for p in host.findall('./ports/extraports')],
            'os_guesses':[{'name':o.get('name',''),'accuracy':o.get('accuracy','')} for o in host.findall('./os/osmatch')]})
    return {'scanner':root.get('scanner',''),'version':root.get('version',''),
        'recorded_start':root.get('startstr',''),'hosts':hosts,
        'summary':{'hosts':len(hosts),'hosts_up':sum(h['status']=='up' for h in hosts),
            'open_ports':sum(p['state']=='open' for h in hosts for p in h['ports'])}}

def inventory(scan):
    rows=[]
    for h in scan['hosts']:
        for p in h['ports']:
            rows.append({'address':h['address'],'host_state':h['status'], **{k:p[k] for k in ['port','protocol','state','service','product','version']}})
        if not h['ports']:
            rows.append({'address':h['address'],'host_state':h['status'],'port':'','protocol':'',
                'state':'No individually listed ports','service':'','product':'','version':''})
    return rows

def markdown(scan):
    def safe(value): return str(value).replace('|',r'\|').replace('\r',' ').replace('\n',' ')
    s=scan['summary']
    lines=['# Recorded network inventory','',f"Recorded scan start: {safe(scan['recorded_start'])}",'',
        f"Hosts in XML: {s['hosts']} · Up: {s['hosts_up']} · Individually listed open ports: {s['open_ports']}",'',
        '| Address | Host state | Port | Protocol | Port state | Service | Product |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for row in inventory(scan): lines.append('| '+' | '.join(safe(row[k]) for k in ['address','host_state','port','protocol','state','service','product'])+' |')
    lines+=['','## Interpretation','',
        'This report describes a recorded scan, not current network state or evidence of compromise. ',
        'OS matches are guesses; filtered and closed ports are not interchangeable. ',
        'Script results and omitted-port aggregates are retained in summary.json for review. ',
        'An open port or unrecognized service alone does not establish a vulnerability.','']
    return '\n'.join(lines)
