#!env/bin/python

import os
import time
import glob
import gzip
import json
import geoip2.database, ipaddr
import urllib3
import IPy
from pprint import pprint
from datetime import datetime
from elasticsearch import Elasticsearch
import Geohash
from pathlib2 import Path
import socket
from ThreatInfoParser import SysmonParser, WinEventLogParser
ES_SERVER = []




def enrichData(data):
        if data != None:
                if data.has_key('DestinationIp') and data['DestinationIsIpv6'] == 'false':
                        geoData = getGeoData(data['DestinationIp'])
                        if geoData != None:
                            data['DestinationLatitude'] = geoData.location.latitude
                            data['DestinationLongitude'] = geoData.location.longitude
                            data['DestinationCity'] = geoData.city.name
                            data['DestinationCountry'] = geoData.country.name
                        #data['DestinationIpThreatCrowdVotes'] = getThreatCrowdData(data['DestinationIp'])
                if data.has_key('SourceIp') and data['SourceIsIpv6'] == 'false':
                        geoData = getGeoData(data['SourceIp'])
                        if geoData != None:
                            data['SourceLatitude'] = geoData.location.latitude
                            data['SourceLongitude'] = geoData.location.longitude
                            data['SourceCity'] = geoData.city.name
                            data['SourceCountry'] = geoData.country.name
                if data.has_key('Hashes'):
                        hashlist = data['Hashes'].split(",")
                        for strVal in hashlist:
                                finalVal = strVal.split("=")
                                if finalVal != None:
                                        data[finalVal[0]] =  finalVal[1]
        return data

## date handler for placing non iso formatted dates into proper ES format
def date_handler(obj):
        return obj.isoformat() if hasattr(obj, 'isoformat') else obj


MAXMIND_DB = "/opt/Processor/GeoLite2-City.mmdb"
LOG_FILE="/opt/Processor/log/EVENT_PROCESSING.log"
UPLOAD_DIR="/tmp/UploadQueue"
PROCESS_DIR="/tmp/ProcessingQueue"
reader = geoip2.database.Reader(MAXMIND_DB)
def getGeoData(ip):
        addr = IPy.IP(ip)
        if addr.iptype() != 'PRIVATE' and addr.iptype() != 'LOOPBACK':
                try:
                        resource = reader.city(ip)
                        return resource
                except:
                        return None

def getThreatCrowdData(ip):
        retval = {}
        addr = IPy.IP(ip)
        if addr.iptype() != 'PRIVATE' and addr.iptype() != 'LOOPBACK':
                m = urllib3.PoolManager()
                x = m.request('GET','https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={0}'.format(ip))
                result = json.loads(x.data)
                return result

mapping = Path("mappings").read_text()

logfile = open(LOG_FILE,'w')
try:
        es = Elasticsearch(ES_SERVER, http_auth=('',''),port=9200)
except:
    logfile.write("Could not connect to ES Cluster " + ES_SERVER + ".\n")
while True:
    array = glob.glob(os.path.join(UPLOAD_DIR,"*.gz"))
    for fname in array:
        DEST_GZ_FILE = os.path.join(PROCESS_DIR, os.path.basename(fname))
        print DEST_GZ_FILE
        os.rename(fname, DEST_GZ_FILE)
        with gzip.open(DEST_GZ_FILE, 'rb') as f:
                logfile.write("Processing: " + DEST_GZ_FILE + "\n")
                doctype="unknown"
                if os.path.basename(fname).find("sysevt") != -1:
                        doctype="sysevt"
                        for line in f.readlines():
                                data = json.loads(line)
                                data['@timestamp'] = datetime.strptime(data['UtcTime'], "%Y-%m-%d %H:%M:%S.%f").isoformat()
                                data = enrichData(data)
                                print data
                                indexname = "sysmon-" + datetime.utcnow().strftime("%Y%m%d%H")
                                print 'Checking index ' + indexname
                                if not es.indices.exists(index=indexname):
                                        es.indices.create(index=indexname,body=mapping)
                                        print 'created index'
                                try:
                                        print json.dumps(data)
                                        es.index(index=indexname, doc_type = doctype, body=json.dumps(data))
                                except Exception, e:
                                        print "Couldn't do it: %s" % e
        f.close()
        os.remove(DEST_GZ_FILE)
    time.sleep(5)
logfile.close()
