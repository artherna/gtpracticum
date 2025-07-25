class RtuMemory:
    # The __init__ method is the constructor, called when a new object is created
    def __init__(self, name, io, data_type,rtu):
        self.name = name #var_rtu-1_I0
        self.io = io # rtu-1_I0
        self.data_type = data_type #analog
        self.address = '' 
        self.protocol = '' # dnp3/modbus
        self.simulation_element = '' #rtu-1_I0 -> bus-2127.voltage
        self.parent = rtu
        
class RTU:
    def __init__(self, name):
        self.name = name
        self.memory = {}
        self.address = ''

    def add_memory(self,address:str,element:RtuMemory):
        if address not in self.memory:
            self.memory[address] = {}

        self.memory[address][element.protocol] = element
        return True
    
    def get_all_active(self,protocol):

        active = {}
        for a,m in self.memory.items():
            if protocol in m:
                if 'active' in m[protocol].simulation_element and m[protocol].simulation_element not in active:
                    active[m[protocol].simulation_element] = m[protocol]
        return list(active.values())