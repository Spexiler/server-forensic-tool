#!/usr/bin/env python3
"""
出站连接追踪模块 v2.0
从多数据源聚合出站连接信息
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from .utils import safe_execute


class OutboundConnectionTracker:
    """出站连接追踪器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.warnings = []
        self.connections = []
    
    def analyze(self, web_proxy_data: Dict = None, startup_data: Dict = None) -> Dict[str, Any]:
        """执行出站连接追踪"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"出站连接追踪: {msg}")
        
        # 合并其他数据源
        if web_proxy_data:
            self._extract_from_proxy(web_proxy_data)
        if startup_data:
            self._extract_from_startup(startup_data)
        
        return {
            'data': {
                'connections': self.connections,
                'summary': self._generate_summary()
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._scan_firewall_logs()
        self._scan_app_logs()
        self._scan_config_files()
        self._scan_dns_cache()
    
    def _scan_firewall_logs(self):
        """扫描防火墙日志"""
        firewall_logs = [
            Path('/var/log/ufw.log'),
            Path('/var/log/iptables.log'),
            Path('/var/log/kern.log'),
        ]
        
        for log_file in firewall_logs:
            if log_file.exists():
                self._parse_firewall_log(log_file)
        
        for pattern in ['*ufw*log*', '*iptables*log*', '*firewall*log*']:
            for log_file in self.target_dir.rglob(pattern):
                self._parse_firewall_log(log_file)
    
    def _parse_firewall_log(self, log_file: Path):
        """解析防火墙日志"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i > 10000:  # 限制行数
                        break
                    
                    # UFW日志格式
                    if 'UFW' in line or 'DST=' in line:
                        self._extract_dst_from_line(line, 'firewall')
                    
                    # iptables日志
                    if 'DST=' in line:
                        match = re.search(r'DST=([\d.]+)', line)
                        if match:
                            dst_ip = match.group(1)
                            port_match = re.search(r'DPT=(\d+)', line)
                            port = port_match.group(1) if port_match else None
                            
                            self._add_connection(dst_ip, port, 'TCP', 'firewall_log', str(log_file))
        
        except Exception:
            pass
    
    def _extract_dst_from_line(self, line: str, source: str):
        """从日志行提取目标地址"""
        # 提取目标IP
        dst_match = re.search(r'DST=([\d.]+)', line)
        if dst_match:
            dst_ip = dst_match.group(1)
            
            # 提取端口
            port_match = re.search(r'DPT=(\d+)', line)
            port = port_match.group(1) if port_match else None
            
            self._add_connection(dst_ip, port, 'TCP', source, str(line)[:100])
    
    def _scan_app_logs(self):
        """扫描应用日志获取出站连接"""
        log_files = []
        
        for pattern in ['*.log', '*syslog*']:
            log_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描标准目录
        for log_dir in [Path('/var/log/')]:
            if log_dir.exists():
                for log_file in log_dir.glob('*.log'):
                    log_files.append(log_file)
        
        for log_file in log_files[:100]:  # 限制数量
            self._parse_app_log(log_file)
    
    def _parse_app_log(self, log_file: Path):
        """解析应用日志"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(512 * 1024)  # 最多读取512KB
            
            # 搜索URL和IP地址
            urls = re.findall(r'https?://([\w\-\.]+)(?::(\d+))?', content)
            for host, port in urls:
                if host and not host.startswith('localhost') and not host.startswith('127.'):
                    self._add_connection(host, port, 'TCP', 'app_log', str(log_file.name))
            
            # 搜索连接目标
            connections = re.findall(r'(?:connect|connect to|connecting to)\s+([\w\-\.]+)(?::(\d+))?', content, re.IGNORECASE)
            for host, port in connections:
                if host:
                    self._add_connection(host, port, 'TCP', 'app_log', str(log_file.name))
        
        except Exception:
            pass
    
    def _scan_config_files(self):
        """扫描配置文件获取远程服务器信息"""
        config_files = []
        
        for pattern in ['*.conf', '*.ini', '*.json', '*.yaml', '*.yml']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        for config_file in config_files:
            self._parse_config_for_remote(config_file)
    
    def _parse_config_for_remote(self, config_file: Path):
        """从配置文件中提取远程服务器"""
        try:
            content = config_file.read_text(errors='ignore', encoding='utf-8')
            
            # gost配置
            if 'gost' in config_file.name.lower() or 'gost' in content.lower():
                self._extract_from_gost_config(content, str(config_file))
            
            # frp配置
            if 'frp' in config_file.name.lower() or 'frp' in content.lower():
                self._extract_from_frp_config(content, str(config_file))
            
            # 通用远程服务器
            remote_patterns = [
                r'(?:remote|server|host)[s]?[\s=]+["\']?([\w\-\.]+)',
                r'(?:connect|target)[s]?[\s=]+["\']?([\w\-\.]+)',
                r'-u\s+"?([^"\s]+)"?',
                r'--server\s+"?([^"\s]+)"?',
            ]
            
            for pattern in remote_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match and not any(x in match.lower() for x in ['localhost', '127.0.0.1', '0.0.0.0']):
                        self._add_connection(match, None, 'TCP', 'config', str(config_file))
        
        except Exception:
            pass
    
    def _extract_from_gost_config(self, content: str, source: str):
        """从gost配置提取远程服务器"""
        # 提取 -L 和 -F 参数
        # -L 监听本地端口
        # -F 转发到远程
        
        # 提取远程服务器
        remote_match = re.search(r'-F\s+"?([^"\s]+)"?', content)
        if remote_match:
            remote = remote_match.group(1)
            self._add_connection(remote, None, 'TCP', 'gost_config', source)
        
        # 从URL格式提取
        urls = re.findall(r'([^"\':\s]+):(\d+)', content)
        for host, port in urls:
            if host and not any(x in host.lower() for x in ['localhost', '127.0.0.1']):
                self._add_connection(host, port, 'TCP', 'gost_config', source)
    
    def _extract_from_frp_config(self, content: str, source: str):
        """从frp配置提取远程服务器"""
        # 提取server_addr
        server_match = re.search(r'server[_addr]*\s*=\s*"?([^\s"]+)"?', content, re.IGNORECASE)
        if server_match:
            server = server_match.group(1)
            self._add_connection(server, '7000', 'TCP', 'frp_config', source)
        
        # 提取server_port
        port_match = re.search(r'server[_port]*\s*=\s*(\d+)', content, re.IGNORECASE)
        port = port_match.group(1) if port_match else '7000'
        
        if server_match:
            self._add_connection(server_match.group(1), port, 'TCP', 'frp_config', source)
    
    def _scan_dns_cache(self):
        """扫描DNS缓存"""
        dns_logs = [
            Path('/var/log/dnsmasq.log'),
            Path('/var/log/named.log'),
        ]
        
        for log_file in dns_logs:
            if log_file.exists():
                self._parse_dns_log(log_file)
    
    def _parse_dns_log(self, log_file: Path):
        """解析DNS日志"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i > 10000:
                        break
                    
                    # 提取查询的域名
                    queries = re.findall(r'query\[[^\]]+\]\s+(\S+)', line)
                    for domain in queries:
                        self._add_connection(domain, '53', 'UDP', 'dns_log', str(log_file.name))
        
        except Exception:
            pass
    
    def _extract_from_proxy(self, proxy_data: Dict):
        """从代理配置提取远程服务器"""
        proxies = proxy_data.get('proxies', [])
        
        for proxy in proxies:
            for target in proxy.get('upstream', []):
                # 提取域名/IP
                if '://' in target:
                    match = re.search(r'https?://([^:/]+)', target)
                    if match:
                        host = match.group(1)
                        port_match = re.search(r':(\d+)', target)
                        port = port_match.group(1) if port_match else None
                        self._add_connection(host, port, 'TCP', 'proxy_config', proxy.get('config_file', ''))
                else:
                    match = re.match(r'([^:]+)(?::(\d+))?', target)
                    if match:
                        host = match.group(1)
                        port = match.group(2)
                        self._add_connection(host, port, 'TCP', 'proxy_config', proxy.get('config_file', ''))
    
    def _extract_from_startup(self, startup_data: Dict):
        """从启动项提取远程服务器"""
        items = startup_data.get('items', [])
        
        for item in items:
            command = item.get('command', '')
            
            # 提取 -u 参数（常见隧道工具）
            u_match = re.search(r'-u\s+"?([^"\s]+)"?', command)
            if u_match:
                remote = u_match.group(1)
                self._add_connection(remote, None, 'TCP', 'startup_item', item.get('source', ''))
            
            # 提取 --server 参数
            server_match = re.search(r'--server\s+"?([^"\s]+)"?', command)
            if server_match:
                remote = server_match.group(1)
                self._add_connection(remote, None, 'TCP', 'startup_item', item.get('source', ''))
    
    def _add_connection(self, target: str, port: Optional[str], protocol: str, 
                       source_type: str, source_file: str):
        """添加连接记录"""
        # 跳过本地地址
        if not target:
            return
        if target in ['localhost', '127.0.0.1', '0.0.0.0', '::1']:
            return
        if target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.'):
            return
        
        connection = {
            'target': target,
            'port': port,
            'protocol': protocol,
            'source_type': source_type,
            'source': source_file
        }
        
        # 检查是否已存在
        for existing in self.connections:
            if (existing['target'] == target and 
                existing.get('port') == port and
                existing['source_type'] == source_type):
                return
        
        self.connections.append(connection)
    
    def _generate_summary(self) -> Dict:
        """生成摘要"""
        summary = {
            'total_connections': len(self.connections),
            'unique_hosts': len(set(c['target'] for c in self.connections)),
            'by_source_type': defaultdict(int),
            'top_targets': []
        }
        
        for conn in self.connections:
            summary['by_source_type'][conn['source_type']] += 1
        
        # 统计目标出现次数
        target_counts = defaultdict(int)
        for conn in self.connections:
            target_counts[conn['target']] += 1
        
        summary['top_targets'] = [
            {'target': t, 'count': c}
            for t, c in sorted(target_counts.items(), key=lambda x: -x[1])[:10]
        ]
        
        summary['by_source_type'] = dict(summary['by_source_type'])
        return summary


def track_outbound_connections(target_dir: str, timeout: int = 30, 
                               web_proxy_data: Dict = None, 
                               startup_data: Dict = None) -> Dict[str, Any]:
    """便捷函数：追踪出站连接"""
    tracker = OutboundConnectionTracker(target_dir, timeout)
    return tracker.analyze(web_proxy_data, startup_data)
