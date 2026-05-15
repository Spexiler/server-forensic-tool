#!/usr/bin/env python3
"""
后端服务自动发现模块 v2.0
从配置和日志中发现后端服务，建立端口-进程-服务映射
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from .utils import safe_execute


class BackendServiceDiscovery:
    """后端服务发现器"""
    
    # 已知服务签名库
    SERVICE_SIGNATURES = {
        'gost': {
            'keywords': ['gost', 'go tunneling', 'dispatch', 'bidi', 'DispatchCopy'],
            'ports': [],
            'config_patterns': ['gost.conf', 'gost.yaml', 'gost.json']
        },
        'frp': {
            'keywords': ['frpc', 'frps', 'fast reverse proxy', 'frp'],
            'ports': [7000, 7001, 7500],
            'config_patterns': ['frpc.ini', 'frps.ini', 'frp.ini']
        },
        'xray': {
            'keywords': ['xray', 'v2ray-core', 'xray-core'],
            'ports': [10086, 8080, 443],
            'config_patterns': ['config.json', 'config.yaml']
        },
        'v2ray': {
            'keywords': ['v2ray', 'v2fly', 'vmess', 'vless'],
            'ports': [10086, 8080, 443],
            'config_patterns': ['config.json', 'v2ray.json']
        },
        'shadowsocks': {
            'keywords': ['shadowsocks', 'ss-server', 'ss-local'],
            'ports': [8388, 8389],
            'config_patterns': ['shadowsocks.json', 'config.json']
        },
        'brook': {
            'keywords': ['brook', 'brook-server'],
            'ports': [9999],
            'config_patterns': ['brook.json']
        },
        'trojan': {
            'keywords': ['trojan', 'trojan-go'],
            'ports': [443, 8443],
            'config_patterns': ['trojan.json', 'config.json']
        },
        'relay_node': {
            'keywords': ['rel_nodeclient', 'relay', 'relay_node'],
            'ports': [],
            'config_patterns': ['relay', 'relay.conf']
        },
        'nginx': {
            'keywords': ['nginx', 'nginx worker'],
            'ports': [80, 443, 8080],
            'config_patterns': ['nginx.conf']
        },
        'apache': {
            'keywords': ['apache', 'httpd', 'apache2'],
            'ports': [80, 443],
            'config_patterns': ['apache2.conf', 'httpd.conf']
        },
        'mysql': {
            'keywords': ['mysqld', 'mariadb'],
            'ports': [3306],
            'config_patterns': ['my.cnf', 'my.ini']
        },
        'postgresql': {
            'keywords': ['postgres', 'postgresql'],
            'ports': [5432],
            'config_patterns': ['postgresql.conf']
        },
        'redis': {
            'keywords': ['redis-server', 'redis-cli'],
            'ports': [6379],
            'config_patterns': ['redis.conf']
        },
        'mongodb': {
            'keywords': ['mongod', 'mongodb'],
            'ports': [27017, 27018],
            'config_patterns': ['mongod.conf']
        }
    }
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.warnings = []
        self.services = []
        self.port_service_map = defaultdict(set)
        self.process_service_map = {}
    
    def analyze(self, web_proxy_data: Dict = None) -> Dict[str, Any]:
        """执行后端服务发现"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"后端服务发现: {msg}")
        
        # 如果有Web代理数据，使用它来辅助发现
        if web_proxy_data:
            self._analyze_from_proxy(web_proxy_data)
        
        return {
            'data': {
                'services': self.services,
                'port_map': dict(self.port_service_map),
                'service_count': len(self.services)
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        # 从配置中发现
        self._discover_from_configs()
        
        # 从日志中发现
        self._discover_from_logs()
        
        # 从进程列表中发现
        self._discover_from_process_info()
    
    def _analyze_from_proxy(self, proxy_data: Dict):
        """从代理配置中分析后端服务"""
        proxies = proxy_data.get('proxies', [])
        
        for proxy in proxies:
            # 提取代理目标
            upstream = proxy.get('upstream', [])
            for target in upstream:
                # 解析目标地址
                port = self._extract_port_from_target(target)
                if port:
                    self._identify_service_by_port(port, f'via {proxy.get("type", "proxy")}')
    
    def _discover_from_configs(self):
        """从配置文件发现服务"""
        # 扫描所有配置文件
        config_files = []
        
        for pattern in ['*.conf', '*.ini', '*.json', '*.yaml', '*.yml', '*.xml']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描标准目录
        config_dirs = [
            Path('/etc/'),
            Path('/etc/gost/'),
            Path('/etc/frp/'),
            Path('/etc/v2ray/'),
            Path('/etc/shadowsocks/'),
            Path('/www/server/panel/vhost/'),
        ]
        
        for config_dir in config_dirs:
            if config_dir.exists():
                for pattern in ['*.conf', '*.ini', '*.json', '*.yaml', '*.yml']:
                    config_files.extend(config_dir.glob(pattern))
        
        for config_file in config_files:
            self._analyze_config_file(config_file)
    
    def _analyze_config_file(self, config_file: Path):
        """分析配置文件"""
        try:
            content = config_file.read_text(errors='ignore', encoding='utf-8')
            
            # 检查文件名是否匹配服务签名
            filename_lower = config_file.name.lower()
            for service_name, signature in self.SERVICE_SIGNATURES.items():
                for pattern in signature['config_patterns']:
                    if pattern.lower() in filename_lower:
                        self._discover_service(service_name, config_file, content)
                        return
            
            # 从内容中搜索关键字
            for service_name, signature in self.SERVICE_SIGNATURES.items():
                for keyword in signature['keywords']:
                    if keyword.lower() in content.lower():
                        self._discover_service(service_name, config_file, content)
                        break
            
        except Exception:
            pass
    
    def _discover_service(self, service_type: str, config_file: Path, content: str):
        """发现服务"""
        # 检查是否已发现
        for existing in self.services:
            if existing['type'] == service_type and existing['config_file'] == str(config_file):
                return
        
        service_info = {
            'type': service_type,
            'config_file': str(config_file),
            'port': None,
            'process': None,
            'details': {}
        }
        
        # 提取端口
        signature = self.SERVICE_SIGNATURES.get(service_type, {})
        ports = signature.get('ports', [])
        
        # 从配置内容中提取端口
        port_match = re.search(r'listen[=:]\s*[\'"]?(\d+)[\'"]?', content, re.IGNORECASE)
        if port_match:
            service_info['port'] = int(port_match.group(1))
        elif ports:
            service_info['port'] = ports[0]
        
        # 提取配置详情
        service_info['details'] = self._extract_config_details(content, service_type)
        
        # 更新端口映射
        if service_info['port']:
            self.port_service_map[service_info['port']].add(service_type)
        
        self.services.append(service_info)
    
    def _extract_config_details(self, content: str, service_type: str) -> Dict:
        """提取配置详情"""
        details = {}
        
        if service_type in ['gost', 'xray', 'v2ray']:
            # 提取远程服务器地址
            remote_match = re.search(r'(?:remote|server)[\s=]+["\']?([^\s"\'\\]+)["\']?', content, re.IGNORECASE)
            if remote_match:
                details['remote_server'] = remote_match.group(1)
            
            # 提取端口
            port_match = re.search(r'port[\s=]+["\']?(\d+)[\'"]?', content, re.IGNORECASE)
            if port_match:
                details['port'] = port_match.group(1)
        
        elif service_type in ['frp']:
            # 提取服务器地址
            server_match = re.search(r'server[_addr]*[\s=]+["\']?([^\s"\'\\]+)["\']?', content, re.IGNORECASE)
            if server_match:
                details['server'] = server_match.group(1)
        
        return details
    
    def _extract_port_from_target(self, target: str) -> Optional[int]:
        """从代理目标提取端口"""
        # 格式: http://host:port, https://host:port, host:port
        match = re.search(r':(\d+)', target)
        if match:
            return int(match.group(1))
        return None
    
    def _discover_from_logs(self):
        """从日志中发现服务"""
        log_files = []
        
        # 扫描日志文件
        for pattern in ['*.log', '*syslog*', '*messages*']:
            log_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描标准日志目录
        log_dirs = [
            Path('/var/log/'),
            Path('/var/log/nginx/'),
            Path('/var/log/apache2/'),
        ]
        
        for log_dir in log_dirs:
            if log_dir.exists():
                for pattern in ['*.log']:
                    log_files.extend(log_dir.glob(pattern))
        
        for log_file in log_files[:50]:  # 限制数量
            self._analyze_log_for_services(log_file)
    
    def _analyze_log_for_services(self, log_file: Path):
        """分析日志文件查找服务签名"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(1024 * 1024)  # 最多读取1MB
            
            # 搜索服务签名
            for service_name, signature in self.SERVICE_SIGNATURES.items():
                for keyword in signature['keywords']:
                    if keyword.lower() in content.lower():
                        # 发现服务但没有配置文件的记录
                        existing = [s for s in self.services if s['type'] == service_name]
                        if not existing:
                            self.services.append({
                                'type': service_name,
                                'config_file': str(log_file),
                                'port': signature['ports'][0] if signature['ports'] else None,
                                'process': keyword,
                                'details': {'discovered_from': 'log'},
                                'source': f'log: {log_file.name}'
                            })
                        break
        
        except Exception:
            pass
    
    def _discover_from_process_info(self):
        """从进程信息发现服务"""
        # 扫描可能的进程相关文件
        for pattern in ['ps*', '*process*', '*proc*']:
            for proc_file in self.target_dir.rglob(pattern):
                self._analyze_process_file(proc_file)
    
    def _analyze_process_file(self, proc_file: Path):
        """分析进程文件"""
        try:
            content = proc_file.read_text(errors='ignore')
            
            for service_name, signature in self.SERVICE_SIGNATURES.items():
                for keyword in signature['keywords']:
                    if keyword.lower() in content.lower():
                        # 提取命令行参数
                        cmdline_match = re.search(r'cmdline[=:\s]+["\']?([^\n]+)["\']?', content)
                        if cmdline_match:
                            cmdline = cmdline_match.group(1)
                            
                            # 检查是否已存在
                            existing = [s for s in self.services if s['type'] == service_name]
                            if not existing:
                                self.services.append({
                                    'type': service_name,
                                    'config_file': str(proc_file),
                                    'port': signature['ports'][0] if signature['ports'] else None,
                                    'process': cmdline[:100],
                                    'details': {'discovered_from': 'process'},
                                    'source': f'process: {proc_file.name}'
                                })
                        break
        
        except Exception:
            pass
    
    def _identify_service_by_port(self, port: int, via: str):
        """根据端口识别服务"""
        # 检查是否已知端口
        for service_name, signature in self.SERVICE_SIGNATURES.items():
            if port in signature.get('ports', []):
                existing = [s for s in self.services if s['port'] == port]
                if not existing:
                    self.services.append({
                        'type': service_name,
                        'config_file': 'discovered',
                        'port': port,
                        'process': f'via {via}',
                        'details': {'discovered_from': 'port_analysis'},
                        'source': f'port: {port}'
                    })
                    self.port_service_map[port].add(service_name)
    
    def get_service_map(self) -> Dict[int, List[str]]:
        """获取端口-服务映射"""
        return {port: list(services) for port, services in self.port_service_map.items()}


def discover_backend_services(target_dir: str, timeout: int = 30, web_proxy_data: Dict = None) -> Dict[str, Any]:
    """便捷函数：发现后端服务"""
    discoverer = BackendServiceDiscovery(target_dir, timeout)
    return discoverer.analyze(web_proxy_data)
