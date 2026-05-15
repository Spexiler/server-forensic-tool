#!/usr/bin/env python3
"""
网络与端口分析模块
用于分析服务器的监听端口、网络服务映射
"""

from typing import Dict, List, Any


class NetworkAnalyzer:
    """网络分析器"""
    
    # 常用端口-服务映射
    PORT_SERVICE_MAP = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
        27018: 'MongoDB',
    }
    
    def __init__(self, service_data: Dict[str, Any]):
        # 兼容新的数据结构（有'data'键或直接是数据）
        self.service_data = service_data.get('data', service_data) if isinstance(service_data, dict) else service_data
        self.network_info = {}
    
    def analyze(self) -> Dict[str, Any]:
        """执行网络分析"""
        self._extract_ports_from_services()
        self._map_ports_to_services()
        self._identify_critical_ports()
        return self.network_info
    
    def _extract_ports_from_services(self):
        """从服务配置中提取端口"""
        all_ports = []
        port_sources = {}
        
        # 从Web服务器提取端口
        if 'web_servers' in self.service_data:
            for server_type, server_info in self.service_data['web_servers'].items():
                if 'listen_ports' in server_info:
                    for port_str in server_info['listen_ports']:
                        port = self._parse_port(port_str)
                        if port:
                            all_ports.append(port)
                            source = f"{server_type}_config"
                            if port not in port_sources:
                                port_sources[port] = []
                            port_sources[port].append(source)
        
        self.network_info['ports'] = list(set(all_ports))
        self.network_info['port_sources'] = port_sources
    
    def _parse_port(self, port_str: str) -> int:
        """解析端口字符串"""
        try:
            # 处理可能带IP的格式，如 0.0.0.0:80
            if ':' in port_str:
                port_part = port_str.split(':')[-1]
                return int(port_part)
            return int(port_str)
        except (ValueError, IndexError):
            return None
    
    def _map_ports_to_services(self):
        """将端口映射到服务"""
        port_service_map = {}
        
        for port in self.network_info.get('ports', []):
            service = self.PORT_SERVICE_MAP.get(port, 'Unknown')
            port_service_map[port] = service
        
        self.network_info['port_service_map'] = port_service_map
    
    def _identify_critical_ports(self):
        """识别关键服务端口"""
        critical_ports = {
            'web': [],
            'database': [],
            'remote_access': [],
            'other': []
        }
        
        for port in self.network_info.get('ports', []):
            service = self.network_info['port_service_map'].get(port, 'Unknown')
            
            if service in ['HTTP', 'HTTPS', 'HTTP-Proxy', 'HTTPS-Alt']:
                critical_ports['web'].append(port)
            elif service in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']:
                critical_ports['database'].append(port)
            elif service in ['SSH', 'RDP', 'Telnet']:
                critical_ports['remote_access'].append(port)
            else:
                critical_ports['other'].append(port)
        
        self.network_info['critical_ports'] = critical_ports
    
    def get_port_summary(self) -> str:
        """获取端口摘要"""
        summary = []
        summary.append(f"发现端口数量: {len(self.network_info.get('ports', []))}")
        
        critical = self.network_info.get('critical_ports', {})
        if critical.get('web'):
            summary.append(f"Web服务端口: {critical['web']}")
        if critical.get('database'):
            summary.append(f"数据库端口: {critical['database']}")
        if critical.get('remote_access'):
            summary.append(f"远程管理端口: {critical['remote_access']}")
        
        return "\n".join(summary)
