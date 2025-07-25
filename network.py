import sys
import struct
from scapy.all import sniff, TCP, IP
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from elasticsearch import Elasticsearch
from datetime import datetime
import xml.etree.ElementTree as ET
from rtu_spec import RtuMemory,RTU
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.constants import Endian
import warnings
import urllib3
import random
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json

MODBUS_PORT = 502
urllib3.disable_warnings()
# Elasticsearch settings
#{"id":"vYP8D5gBpDLYqpZxiXge","name":"my-api-key","api_key":"hZ7rPcfCZrdIQTVoqG5Taw","encoded":"dllQOEQ1Z0JwRExZcXBaeGlYZ2U6aFo3clBjZkNacmRJUVRWb3FHNVRhdw=="}
ES_HOST = "https://172.16.50.2:9200"  # Use your Elasticsearch HTTPS endpoint
ES_INDEX = "modbus-traffic"  # Your Elasticsearch index
API_KEY = "dllQOEQ1Z0JwRExZcXBaeGlYZ2U6aFo3clBjZkNacmRJUVRWb3FHNVRhdw=="  # API key from Elasticsearch
rtu_map = {'suscount':0}
rtu_ip = {'10.1.31.101':'rtu1','10.1.31.102':'rtu2','10.1.31.103':'rtu3','10.1.31.104':'rtu4','10.1.31.105':'rtu5','10.1.31.106':'rtu6','10.1.31.107':'rtu7'}
conn_track = {}
suscount = 0

# Initialize Elasticsearch client with API key and SSL verification
es = Elasticsearch(
    ES_HOST,
    api_key=API_KEY,  # Use the API key for authentication
    verify_certs=False,  # Verify the server certificate (set to False if self-signed)
    # If using self-signed certificates, you can specify the CA certificate
    # ca_certs="/path/to/your/ca.crt"
)

def parse_modbus(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == MODBUS_PORT or packet[TCP].sport == MODBUS_PORT):
        try:
            payload = bytes(packet[TCP].payload)
            if payload:
                # If Modbus Request
                if packet.haslayer(ModbusADURequest):
                    modbus_layer = packet.getlayer(ModbusADURequest)
                    function_code = get_function_code(modbus_layer.funcCode)
                    if packet[IP].src in rtu_ip:
                        rtu = rtu_map[rtu_ip[packet[IP].src]]
                    elif packet[IP].dst in rtu_ip:
                        rtu = rtu_map[rtu_ip[packet[IP].dst]]
                    else:
                        rtu = None
                    
                    try:
                        outputs = modbus_layer.payload.outputsValue
                    except Exception as ex:
                        outputs = 'N/A'
                    if packet[TCP].sport == 502 or packet[TCP].dport == 502:
                        protocol = 'modbus'
                        se = []
                        if rtu != None:
                            if modbus_layer.funcCode == 5 or modbus_layer.funcCode == 6:
                                se.append(rtu.memory[str(modbus_layer.payload.fields['outputAddr'])][protocol].simulation_element)
                            elif 'quantity' in modbus_layer.payload.fields:
                                for i in range(0,modbus_layer.payload.fields['quantity']):
                                    se.append(rtu.memory[str(modbus_layer.payload.fields['startAddr']+i)][protocol].simulation_element)
                            else:
                                try:
                                    se.append(rtu.memory[str(modbus_layer.payload.fields['startAddr'])][protocol].simulation_element)
                                except:
                                    se = 'N/A'
                        else:
                            se = 'N/A'
                        if packet[TCP].dport == 502:
                            if packet[IP].dst not in conn_track:
                                conn_track[packet[IP].dst] = {}
                            if modbus_layer.funcCode not in conn_track[packet[IP].dst]:
                                conn_track[packet[IP].dst][modbus_layer.funcCode] = {'request':{},'response':{}}
                            conn_track[packet[IP].dst][modbus_layer.funcCode]['request'] = {'se':se}
                    else:
                        protocol = 'ip'
                        se = 'N/A'
                    
                    if isSuspicious(packet,modbus_layer,modbus_layer.funcCode,se,rtu):
                        sus = 'Suspicious: Detrimental'
                    else:
                        sus = 'Good'
                    packet_data = {
                        "timestamp": datetime.now(),
                        "src_ip": packet[IP].src,
                        "src_port": packet[TCP].sport,
                        "dst_ip": packet[IP].dst,
                        "dst_port": packet[TCP].dport,
                        "protocol": protocol,
                        "function_code": function_code,
                        "payload_fields": get_payload_fields(modbus_layer.payload.fields),
                        "packet_type": "request",
                        "outputs_value": outputs,
                        "simulation_element": se,
                        "ids_status": sus
                    }
                    send_to_elasticsearch(packet_data)

                # If Modbus Response
                elif packet.haslayer(ModbusADUResponse):
                    modbus_layer = packet.getlayer(ModbusADUResponse)
                    function_code = get_function_code(modbus_layer.funcCode)
                    se = 'N/A'
                    if packet[IP].src in rtu_ip:
                        rtu = rtu_map[rtu_ip[packet[IP].src]]
                    elif packet[IP].dst in rtu_ip:
                        rtu = rtu_map[rtu_ip[packet[IP].dst]]
                    else:
                        rtu = None

                    sus = 'Good'
                    sus2 = ''
                    try:
                        outputs = modbus_layer.payload.outputsValue
                    except Exception as ex:
                        outputs = 'N/A'
                    if packet[TCP].sport == 502 or packet[TCP].dport == 502:
                        protocol = 'modbus'
                    else:
                        protocol = 'ip'
                        
                    payload_fields = []
                    if modbus_layer.funcCode == 1 or modbus_layer.funcCode == 2:
                        if modbus_layer.funcCode == 1:
                            arr = modbus_layer.payload.fields['coilStatus']
                        else:
                            arr = modbus_layer.payload.fields['inputStatus']
                        for i in arr:
                            payload_fields.extend(int_to_bool_array(i))
                    elif modbus_layer.funcCode == 4:
                        #payload_fields = get_payload_fields(modbus_layer.payload.fields)
                        uints = modbus_layer.payload.fields['registerVal']
                        values = []
                        se = []
                        if packet[TCP].sport == 502:
                            if packet[IP].src in conn_track:
                                if modbus_layer.funcCode in conn_track[packet[IP].src]:
                                    se = conn_track[packet[IP].src][modbus_layer.funcCode]['request']['se']
                        for i in range(0,len(uints)):
                            if len(se) == 0:
                                values.append(get_value(i,1800,-600,65535))
                            else:
                                val = get_value(uints[i],1800,-600,65535)
                                readings = read_provider_objects(se)
                                trusted_val = readings[se[i]]['avg']

                                diff = 0
                                if val > trusted_val:
                                    diff = val - trusted_val
                                else:
                                    diff = trusted_val - val
                                try:
                                    percent = diff / trusted_val * 100
                                except:
                                    #print(readings[se[i]])
                                    percent = diff
                                if percent < 0:
                                    percent = percent * -1
                                if percent >= 1.0:
                                    sus = 'Suspicious: Reading does not match simulation'
                                    sus2 = f'{se[i]} with suspicious reading {val}'

                                #print(f'{percent}%')
                                values.append(f'{se[i]}={val}')
                        try:
                            del conn_track[packet[IP].src][modbus_layer.funcCode]
                        except:
                            print(f'Issue deleteing {packet[IP].src}:{modbus_layer.funcCode}')
                        payload_fields = get_payload_fields(modbus_layer.payload.fields)
                        outputs = values

                    else:
                        payload_fields = get_payload_fields(modbus_layer.payload.fields)
                    packet_data = {
                        "timestamp": datetime.now(),
                        "src_ip": packet[IP].src,
                        "src_port": packet[TCP].sport,
                        "dst_ip": packet[IP].dst,
                        "dst_port": packet[TCP].dport,
                        "protocol": protocol,
                        "function_code": function_code,
                        "payload_fields": payload_fields,
                        "packet_type": "response",
                        "outputs_value": outputs,
                        "simulation_element": se,
                        "ids_status": sus,
                        "suspicious_detail":sus2
                    }
                    send_to_elasticsearch(packet_data)

        except Exception as e:
            print(f"Error parsing Modbus packet: {e}")

def get_payload_fields(payload):
    s = ''
    for k, v in payload.items():
        if 'funcCode' in k:
            continue
        s += f'{k}:{v}\t'
    return s.strip()

def get_function_code(func_code):
    # Add mapping for function codes to more human-readable names
    func_mapping = {
        1: 'Read Coils',
        2: 'Read Discrete Inputs',
        3: 'Read Holding Registers',
        4: 'Read Input Registers',
        5: 'Write Single Coil',
        6: 'Write Single Register',
        15: 'Write Multiple Coils',
        16: 'Write Multiple Registers'
    }
    return func_mapping.get(func_code, f"Unknown ({func_code})")

def send_to_elasticsearch(packet_data):
    try:
        # Send packet data to Elasticsearch
        #write_to_debug(packet_data)
        response = es.index(index=ES_INDEX, body=packet_data)
        #print(f"Sent to Elasticsearch: {response['_id']}:{packet_data['function_code']}:{packet_data['packet_type']}")
    except Exception as e:
        print(f"Error sending to Elasticsearch: {e}")

def write_to_debug(packet_data):

    with open('/home/aherna4/gt/values.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        data = []
        # Write the data
        if packet_data["outputs_value"] != 'N/A':
            for d in packet_data["outputs_value"]:
                data.append(d)
            writer.writerow(data)

def isSuspicious(packet,modbus_layer,func_code,tag,rtu):
    active = rtu.get_all_active('modbus')
    if '10.1.31.' in packet[IP].dst and func_code == 15: ## create a filter
        if modbus_layer.payload.outputsValue[0] == 0:
            values_old = read_provider_objects(active)
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {tag} --status false"))
            values_new = read_provider_objects(active)
            for k,v in values_old:
                if '.load_mw' in k:
                    if values_new[k] < values_old[k]:
                        return True
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {tag} --status true"))
    elif '10.1.31.' in packet[IP].dst and func_code == 5:
        if modbus_layer.payload.outputValue == 0:
            values_old = read_provider_objects(active)
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {tag} --status false"))
            values_new = read_provider_objects(active)
            for k,v in values_old:
                if '.load_mw' in k:
                    if values_new[k] < values_old[k]:
                        return True
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {tag} --status true"))
    return False

def xml_to_dict(element):
    """Recursively convert an XML element and its children to a dictionary."""
    if len(element) == 0:  # If the element has no children
        return element.text.strip() if element.text else None

    result = {}
    for child in element:
        child_dict = xml_to_dict(child)
        if child.tag in result:
            # If the tag already exists, convert it to a list
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_dict)
        else:
            result[child.tag] = child_dict

    return result

def read_xml_file(file_path):
    """Read an XML file and convert it to a dictionary."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    return {root.tag: xml_to_dict(root)}

def process_config(config):
    tags = config['SCEPTRE']['field-device']['tags']['external-tag']
    comms = config['SCEPTRE']['field-device']['comms']
    input = config['SCEPTRE']['field-device']['input']
    output = config['SCEPTRE']['field-device']['output']
    memory_elements = {}
    provider_tags = {}
    rtu = RTU(config["SCEPTRE"]["field-device"]["name"])
    ## Process tags
    for t in tags:
        if t['name'] not in memory_elements:
            e = RtuMemory(t['name'],t['io'],t['type'],rtu)
            memory_elements[t['name']] = e
            provider_tags[t['io']] = e
        else:
            print(f'Collision with {t["name"]}')
    
    ## Process comms
    for protocol,d in comms.items():
        protocol = protocol.split('-')[0]
        if protocol == 'dnp3':
            for da in d['analog-input']:
                memory_elements[da['tag']].address = da['address']
                
                if memory_elements[da['tag']].protocol != '':
                    print(f"protocol collision {da['tag']}")
                memory_elements[da['tag']].protocol = protocol
                rtu.add_memory(memory_elements[da['tag']].address,memory_elements[da['tag']])
            for di in d['binary-input']:
                memory_elements[di['tag']].address = di['address']
                
                if memory_elements[di['tag']].protocol != '':
                    print(f"protocol collision {di['tag']}")
                memory_elements[di['tag']].protocol = protocol
                rtu.add_memory(memory_elements[di['tag']].address,memory_elements[di['tag']])
            for do in d['binary-output']:
                memory_elements[do['tag']].address = do['address']
                
                if memory_elements[do['tag']].protocol != '':
                    print(f"protocol collision {do['tag']}")
                memory_elements[do['tag']].protocol = protocol
                rtu.add_memory(memory_elements[do['tag']].address,memory_elements[do['tag']])
        else:
            for ir in d['input-register']:
                memory_elements[ir['tag']].address = ir['address']
                
                if memory_elements[ir['tag']].protocol != '':
                    print(f"protocol collision {ir['tag']}")
                memory_elements[ir['tag']].protocol = protocol
                rtu.add_memory(memory_elements[ir['tag']].address,memory_elements[ir['tag']])
            for ir in d['discrete-input']:
                memory_elements[ir['tag']].address = ir['address']
                
                if memory_elements[ir['tag']].protocol != '':
                    print(f"protocol collision {ir['tag']}")
                memory_elements[ir['tag']].protocol = protocol
                rtu.add_memory(memory_elements[ir['tag']].address,memory_elements[ir['tag']])
            for ir in d['coil']:
                memory_elements[ir['tag']].address = ir['address']
                
                if memory_elements[ir['tag']].protocol != '':
                    print(f"protocol collision {ir['tag']}")
                memory_elements[ir['tag']].protocol = protocol
                rtu.add_memory(memory_elements[ir['tag']].address,memory_elements[ir['tag']])

    ## Process Input from provider
    for e in input['analog']:
        provider_tags[e['id']].simulation_element = e['name']
    for e in input['binary']:
        provider_tags[e['id']].simulation_element = e['name']

    ## Process Output to provider
    for e in output['binary']:
        provider_tags[e['id']].simulation_element = e['name']

    print(f'Finished with {config["SCEPTRE"]["field-device"]["name"]}')
    return rtu

def int_to_bool_array(n):
    """Convert an integer to an array of booleans based on its binary representation."""
    # Convert the integer to binary and remove the '0b' prefix
    binary_representation = bin(n)[2:]
    
    # Create a list of booleans: True for '1' and False for '0'
    bool_array = [bit == '1' for bit in binary_representation]
    bool_array.reverse()
    return bool_array

def get_value(measure,max,min,c16bitScale):
    slope = c16bitScale / (max - min)
    intercept = -(slope * min)
    value = (measure - intercept) / slope
    return value

def is_float(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
    
def is_bool(s):
    try:
        if str(s).lower() == 'true':
            return True
        return False
    except ValueError:
        return False

def read_provider_objects(provider_tags):
    provider_objects = {}
    count = 0
    commands = []
    for p in provider_tags:
        commands.append(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command read --tag {p}")
        provider_objects[p] = ''

    results = run_commands_with_pool(commands)
    for k,v in results.items():
        ret = parse_command(v)
        if len(ret) == 0:
            continue
        ret = parse_command(v)[0]
        if is_bool(ret):
            provider_objects[k] = bool(ret)
        elif is_float(ret):
            provider_objects[k] = float(ret)
        else:
            provider_objects[k] = ret

    return provider_objects

def parse_command(output:str):
    lines = output.splitlines()
    start = False
    parsed_output = []
    for l in lines:
        if 'Reply:' in l:
            start = True
            continue
        if not start:
            continue
        parsed_output.append(l.strip())
    return parsed_output

def execute_single_command(command):
    """
    Executes a shell command and returns a tuple of (command, output).
    """
    try:
        result = subprocess.run(command, shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
    except subprocess.CalledProcessError as e:
        output = f"Error:\n{e.stderr}\n{e.stdout}"
    
    return (command, output)

def run_commands_with_pool(commands, max_workers=1):
    """
    Runs commands in parallel using a thread pool.

    Args:
        commands (list): List of shell command strings.
        max_workers (int): Max number of threads to use.

    Returns:
        dict: Dictionary with command as key and output as value.
    """
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        start_time = time.time()
        future_to_command = {executor.submit(execute_single_command, cmd): cmd for cmd in commands}
        
        for future in as_completed(future_to_command):
            cmd, output = future.result()
            results[cmd.split(' ')[-1]] = output
        end_time = time.time()
        elapsed_time = end_time - start_time

    return results

def print_dict(d):
    for k,v in d.items():
        print(f'{k}\t{v}')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 modbus_traffic_analyzer.py <interface>")
        sys.exit(1)
    configs = {}
    
    for i in range(1,8):
        configs[f'rtu{i}'] = read_xml_file(f'/home/aherna4/gt/rtu{i}.config')

    for k,f in configs.items():
        rtu_map[k] = process_config(f)
    interface = sys.argv[1]
    print(f"Starting Modbus traffic analyzer on interface: {interface}...")
    sniff(
        iface=interface,  # You can specify the interface here via command-line argument
        filter=f"tcp port {MODBUS_PORT}",
        prn=parse_modbus,
        store=0,
    )

if __name__ == "__main__":
    main()