import json, re
from datetime import datetime
import pandas as pd
import codecs

with open('/home/gonzalo/Escritorio/IBERDROLA/snort.json') as myfile:
	data=myfile.readlines()


dataset = []

for d in data:
	data = json.loads(d[d.find('{'):])
	new = {}
	new['platform'] = 'snort'
	new['source-ip'] = data['event']['source-ip']
	new['destination-ip'] = data['event']['destination-ip']
	new['time'] = datetime.fromtimestamp(data['event']['event-second']).strftime("%d/%m/%Y, %H:%M:%S")
	new['alert'] = data['event']['signature-id']
	new['priority'] = data['event']['priority']
	new['hostname'] = ''
	new['full_log'] = ''
	new['source-port'] = ''
	new['destination-port'] = ''
	dataset.append(new)


with open('/home/gonzalo/Escritorio/IBERDROLA/ossec.json') as myfile1:
	data1=myfile1.readlines()

for d1 in data1:
	data1 = json.loads(d1[d1.find('{'):])
	new1 = {}
	new1['platform'] = 'ossec'
	new1['source-ip'] = ''
	new1['destination-ip'] = ''
	new1['time'] = datetime.fromtimestamp(data1['TimeStamp']/1000).strftime("%d/%m/%Y, %H:%M:%S")
	new1['alert'] = data1['rule']['comment']
	new1['priority'] = data1['rule']['level']
	new1['hostname'] = data1['hostname']
	new1['full_log'] = data1['full_log']
	new1['source-port'] = ''
	new1['destination-port'] = ''
	dataset.append(new1)


with open('/home/gonzalo/Escritorio/IBERDROLA/wazuh.json') as myfile2:
	data2=myfile2.readlines()

for d2 in data2:
	data2 = json.loads(d2[d2.find('{'):])
	new2 = {}
	new2['platform'] = 'wazuh'
	new2['source-ip'] = ''
	new2['destination-ip'] = ''
	new2['time'] = datetime.strptime(data2['timestamp'][:18],'%Y-%m-%dT%H:%M:%S').strftime("%d/%m/%Y, %H:%M:%S")
	new2['alert'] = data2['rule']['description']
	new2['priority'] = data2['rule']['level']
	new2['hostname'] = data2['agent']['name']
	new2['full_log'] = data2['full_log']
	new2['source-port'] = ''
	new2['destination-port'] = ''
	dataset.append(new2)

with open('/home/gonzalo/Escritorio/IBERDROLA/suricata.txt') as myfile3:
	data3=myfile3.readlines()

alerts=[]
anomaly=[]
for d3 in data3:
	dat = json.loads(d3[d3.find('{'):])
	if(dat['event_type']=='alert'):
		alerts.append(dat)
	if(dat['event_type']=='anomaly'):
		anomaly.append(dat)


for al in alerts:
	new3={}
	new3['platform'] = 'suricata'
	new3['source-ip'] = al['src_ip']
	new3['destination-ip'] = al['dest_ip']
	new3['source-port'] = al['src_port']	
	new3['destination-port'] = al['dest_port']
	new3['time'] = datetime.strptime(al['timestamp'][:18],'%Y-%m-%dT%H:%M:%S').strftime("%d/%m/%Y, %H:%M:%S")
	new3['alert'] = al['alert']['signature_id']
	new3['priority'] = al['alert']['severity']
	new3['hostname'] = ''
	new3['full_log'] = al['alert']['signature']
	dataset.append(new3)

for an in anomaly:
	new3={}
	new3['platform'] = 'suricata'
	new3['source-ip'] = an['src_ip']
	new3['destination-ip'] = an['dest_ip']
	new3['source-port'] = an['src_port']
	new3['destination-port'] = an['dest_port']
	new3['time'] = datetime.strptime(an['timestamp'][:18],'%Y-%m-%dT%H:%M:%S').strftime("%d/%m/%Y, %H:%M:%S")
	new3['alert'] = 'anomaly'
	new3['priority'] = ''
	new3['hostname'] = ''
	new3['full_log'] = an['anomaly']['event']
	dataset.append(new3)

with open('/home/gonzalo/Escritorio/IBERDROLA/dataset.json', 'w') as f:
    json.dump(dataset, f)

