import uuid
import ipaddress
from core.evasions.Evasion import Evasion
from core.engines.EvasionComponent import EvasionComponent
from core.engines.DefineComponent import DefineComponent
from core.controlers.Module import Module
from core.engines.CodeComponent import CodeComponent
from core.engines.CallComponent import CallComponent

class iprange(Evasion):
    def __init__(self, platform, args=None):
        super().__init__(platform, args)
        if not args or len(args) == 0:
            raise ValueError("IP evasion module requires a CIDR argument (-em iprange:192.168.1.0/24)")
        
        try:
            self.network = ipaddress.ip_network(args[0])
            self.network_address = str(self.network.network_address)
            self.netmask = str(self.network.netmask)
            
            # Convert CIDR to wildcard format for VBA (e.g., 192.168.1.* for /24)
            parts = str(self.network.network_address).split('.')
            prefix_len = self.network.prefixlen
            wildcard_parts = []
            
            for i in range(4):
                if prefix_len >= 8:
                    wildcard_parts.append(parts[i])
                    prefix_len -= 8
                else:
                    wildcard_parts.append('*')
            
            self.ip_wildcard = '.'.join(wildcard_parts)
            self.uuid = uuid.uuid4().hex
        except ValueError as e:
            raise ValueError(f"Invalid CIDR format: {e}")

    def translate(self):
        module = Module()
        module.name = self.__class__.__name__
        code = self.template()

        if self.platform == "windows_cs":
            module.components = [
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####NETWORK_ADDRESS####", self.network_address)
                                .replace("####NETMASK####", self.netmask)),
                EvasionComponent(f"IPRangeCheck{self.uuid}.CheckIPRange();")
            ]
        elif self.platform == "windows_cpp":
            module.components = [
                DefineComponent("#include <winsock2.h>\n#include <ws2tcpip.h>\n#include <iphlpapi.h>\n"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####NETWORK_ADDRESS####", self.network_address)
                                .replace("####NETMASK####", self.netmask)),
                EvasionComponent(f"CheckIPRange{self.uuid}();")
            ]
            module.mingw_options = "-liphlpapi -lws2_32 "
        elif self.platform == "windows_vba":
            module.components = [
                EvasionComponent(f"CheckIPRange{self.uuid}"),
                CodeComponent(code.replace("####UUID####", self.uuid)
                                .replace("####IP_WILDCARD####", self.ip_wildcard))
            ]

        return module