from pathlib import Path
import tempfile
import unittest
from network_report.parser import parse_scan, inventory, markdown

class ScanTests(unittest.TestCase):
    def test_bundled_scan(self):
        p=Path(__file__).resolve().parents[1]/'data/scans/network_scan.xml'
        d=parse_scan(p)
        self.assertEqual(d['summary'],{'hosts':4,'hosts_up':4,'open_ports':2})
        self.assertEqual(len(inventory(d)),4)
        self.assertIn('192.168.204.1',markdown(d))
        self.assertTrue(any(p['scripts'] for h in d['hosts'] for p in h['ports']))
    def test_empty_valid_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'scan.xml';p.write_text('<nmaprun scanner="nmap"/>')
            self.assertEqual(parse_scan(p)['summary']['hosts'],0)
    def test_invalid_xml_and_entities(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'scan.xml'
            for text in ['broken','<unrelated/>','<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun/>']:
                p.write_text(text)
                with self.assertRaises(ValueError): parse_scan(p)
    def test_closed_ports_are_not_counted_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'scan.xml'
            p.write_text('<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>')
            self.assertEqual(parse_scan(p)['summary']['open_ports'],0)

if __name__=='__main__': unittest.main()
