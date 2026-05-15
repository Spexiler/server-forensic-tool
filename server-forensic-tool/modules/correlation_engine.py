#!/usr/bin/env python3
"""
多数据源关联分析引擎 v2.0
将不同数据源的信息关联起来，还原完整的服务架构
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from .utils import safe_execute


class CorrelationEngine:
    """多数据源关联分析引擎"""
    
    def __init__(self):
        self.data_sources = {}
        self.correlations = []
        self.architecture = {}
    
    def analyze(self, 
                web_proxy_data: Dict = None,
                access_log_data: Dict = None,
                backend_services: Dict = None,
                startup_items: Dict = None,
                ssh_security: Dict = None,
                log_files: Dict = None,
                database_services: Dict = None,
                outbound_connections: Dict = None,
                services: Dict = None,
                network: Dict = None) -> Dict[str, Any]:
        """执行多数据源关联分析"""
        
        # 收集所有数据源
        self.data_sources = {
            'web_proxy': web_proxy_data or {},
            'access_log': access_log_data or {},
            'backend_services': backend_services or {},
            'startup_items': startup_items or {},
            'ssh_security': ssh_security or {},
            'log_files': log_files or {},
            'databases': database_services or {},
            'outbound_connections': outbound_connections or {},
            'services': services or {},
            'network': network or {}
        }
        
        # 执行关联分析
        self._correlate_all()
        
        # 构建完整架构
        self._build_complete_architecture()
        
        return {
            'data': {
                'correlations': self.correlations,
                'architecture': self.architecture,
                'data_source_summary': self._summarize_data_sources()
            },
            'warnings': []
        }
    
    def _correlate_all(self):
        """执行所有关联分析"""
        # 1. 端口关联分析
        self._correlate_port_services()
        
        # 2. IP关联分析
        self._correlate_ip_services()
        
        # 3. 配置-启动项关联
        self._correlate_config_startup()
        
        # 4. 服务链路关联
        self._correlate_service_chain()
        
        # 5. 出站连接关联
        self._correlate_outbound()
    
    def _correlate_port_services(self):
        """端口-服务关联"""
        correlations = []
        
        # 从网络配置获取端口映射
        network = self.data_sources.get('network', {})
        port_map = network.get('port_service_map', {})
        
        # 从后端服务获取端口
        backend = self.data_sources.get('backend_services', {})
        services = backend.get('data', {}).get('services', [])
        
        for service in services:
            port = service.get('port')
            if port and port in port_map:
                correlations.append({
                    'type': 'port_service',
                    'port': port,
                    'service': service.get('type'),
                    'sources': ['network', 'backend_service']
                })
            elif port:
                correlations.append({
                    'type': 'port_service',
                    'port': port,
                    'service': service.get('type'),
                    'sources': ['backend_service']
                })
        
        # 从Web代理获取端口
        proxy = self.data_sources.get('web_proxy', {})
        proxies = proxy.get('data', {}).get('proxies', [])
        
        for p in proxies:
            listen_port = p.get('listen_port')
            if listen_port:
                correlations.append({
                    'type': 'web_proxy_port',
                    'port': listen_port,
                    'server_name': p.get('server_name', ['default'])[0],
                    'type': p.get('type'),
                    'sources': ['web_proxy']
                })
        
        self.correlations.extend(correlations)
    
    def _correlate_ip_services(self):
        """IP-服务关联"""
        # 从访问日志获取IP
        access = self.data_sources.get('access_log', {})
        top_ips = access.get('data', {}).get('top_ips', {})
        
        # 从SSH安全获取攻击IP
        ssh = self.data_sources.get('ssh_security', {})
        ssh_data = ssh.get('data', {})
        attacker_ips = ssh_data.get('top_attackers', [])
        
        # 关联
        for ip, count in list(top_ips.items())[:20]:
            # 检查是否是攻击IP
            is_attacker = any(ip == a[0] for a in attacker_ips)
            
            self.correlations.append({
                'type': 'ip_access',
                'ip': ip,
                'request_count': count,
                'classification': 'attacker' if is_attacker else 'visitor',
                'sources': ['access_log']
            })
    
    def _correlate_config_startup(self):
        """配置-启动项关联"""
        # 从后端服务获取配置
        backend = self.data_sources.get('backend_services', {})
        services = backend.get('data', {}).get('services', [])
        
        # 从启动项获取命令
        startup = self.data_sources.get('startup_items', {})
        items = startup.get('data', {}).get('items', [])
        
        # 关联相似名称
        for service in services:
            service_name = service.get('type', '').lower()
            for item in items:
                item_name = item.get('name', '').lower()
                item_cmd = item.get('command', '').lower()
                
                if service_name in item_name or service_name in item_cmd:
                    self.correlations.append({
                        'type': 'config_startup',
                        'service': service.get('type'),
                        'startup_name': item.get('name'),
                        'startup_command': item.get('command')[:50],
                        'startup_source': item.get('source'),
                        'sources': ['backend_service', 'startup_item']
                    })
    
    def _correlate_service_chain(self):
        """服务链路关联 - 核心功能"""
        chain = {
            'entry_points': [],
            'proxy_layer': [],
            'backend_services': [],
            'data_layer': [],
            'outbound_connections': []
        }
        
        # 入口点（Web服务器）
        proxy = self.data_sources.get('web_proxy', {})
        proxies = proxy.get('data', {}).get('proxies', [])
        
        for p in proxies:
            chain['entry_points'].append({
                'type': p.get('type', 'web'),
                'listen': p.get('listen_port'),
                'server_name': p.get('server_name', []),
                'upstream': p.get('upstream', [])
            })
            
            # 代理层
            for upstream in p.get('upstream', []):
                chain['proxy_layer'].append({
                    'source': p.get('type'),
                    'target': upstream
                })
        
        # 后端服务
        backend = self.data_sources.get('backend_services', {})
        services = backend.get('data', {}).get('services', [])
        
        for service in services:
            chain['backend_services'].append({
                'type': service.get('type'),
                'port': service.get('port'),
                'config': service.get('config_file')
            })
        
        # 数据层
        databases = self.data_sources.get('databases', {})
        db_list = databases.get('data', {}).get('databases', [])
        
        for db in db_list:
            chain['data_layer'].append({
                'type': db.get('type'),
                'port': db.get('port'),
                'status': db.get('status')
            })
        
        # 出站连接
        outbound = self.data_sources.get('outbound_connections', {})
        connections = outbound.get('data', {}).get('connections', [])
        
        for conn in connections:
            chain['outbound_connections'].append({
                'target': conn.get('target'),
                'port': conn.get('port'),
                'source': conn.get('source')
            })
        
        self.correlations.append({
            'type': 'service_chain',
            'chain': chain
        })
    
    def _correlate_outbound(self):
        """出站连接关联"""
        outbound = self.data_sources.get('outbound_connections', {})
        connections = outbound.get('data', {}).get('connections', [])
        
        # 从启动项查找远程服务器配置
        startup = self.data_sources.get('startup_items', {})
        items = startup.get('data', {}).get('items', [])
        
        for conn in connections:
            target = conn.get('target')
            source = conn.get('source')
            
            # 检查是否来自启动项
            for item in items:
                if target in item.get('command', ''):
                    self.correlations.append({
                        'type': 'outbound_startup',
                        'target': target,
                        'startup_name': item.get('name'),
                        'source_type': source
                    })
    
    def _build_complete_architecture(self):
        """构建完整架构"""
        self.architecture = {
            'layers': [],
            'connections': [],
            'security_findings': []
        }
        
        # Layer 0: 外部客户端
        self.architecture['layers'].append({
            'layer': 0,
            'name': '外部客户端',
            'type': 'client',
            'components': []
        })
        
        # Layer 1: 入口层（防火墙/网关）
        entry_layer = {
            'layer': 1,
            'name': '入口层',
            'type': 'gateway',
            'components': []
        }
        
        # 添加防火墙信息
        log_files = self.data_sources.get('log_files', {})
        anomalies = log_files.get('data', {}).get('anomalies', [])
        
        if anomalies:
            entry_layer['components'].append({
                'name': '防火墙',
                'status': 'active',
                'note': f'发现{len(anomalies)}个日志异常'
            })
        
        self.architecture['layers'].append(entry_layer)
        
        # Layer 2: Web层
        web_layer = {
            'layer': 2,
            'name': 'Web层',
            'type': 'web',
            'components': []
        }
        
        proxy = self.data_sources.get('web_proxy', {})
        proxies = proxy.get('data', {}).get('proxies', [])
        
        for p in proxies:
            web_layer['components'].append({
                'name': f"{p.get('type', 'web').upper()}服务器",
                'listen': p.get('listen_port'),
                'domains': p.get('server_name', []),
                'type': 'web_server'
            })
        
        if web_layer['components']:
            self.architecture['layers'].append(web_layer)
        
        # Layer 3: 应用层
        app_layer = {
            'layer': 3,
            'name': '应用层',
            'type': 'application',
            'components': []
        }
        
        backend = self.data_sources.get('backend_services', {})
        services = backend.get('data', {}).get('services', [])
        
        for service in services:
            app_layer['components'].append({
                'name': service.get('type', 'unknown'),
                'port': service.get('port'),
                'config': service.get('config_file'),
                'type': 'backend_service'
            })
        
        startup = self.data_sources.get('startup_items', {})
        items = startup.get('data', {}).get('items', [])
        
        # 特别标记隧道服务
        tunnel_summary = startup.get('data', {}).get('summary', {}).get('tunnel_services', [])
        for tunnel in tunnel_summary:
            app_layer['components'].append({
                'name': tunnel.get('name'),
                'command': tunnel.get('command', '')[:50],
                'source': tunnel.get('source'),
                'type': 'tunnel_service'
            })
        
        if app_layer['components']:
            self.architecture['layers'].append(app_layer)
        
        # Layer 4: 数据层
        data_layer = {
            'layer': 4,
            'name': '数据层',
            'type': 'database',
            'components': []
        }
        
        databases = self.data_sources.get('databases', {})
        db_list = databases.get('data', {}).get('databases', [])
        
        for db in db_list:
            data_layer['components'].append({
                'name': db.get('type', 'db'),
                'port': db.get('port'),
                'status': db.get('status'),
                'type': 'database'
            })
        
        if data_layer['components']:
            self.architecture['layers'].append(data_layer)
        
        # Layer 5: 外部网络
        external_layer = {
            'layer': 5,
            'name': '外部网络',
            'type': 'external',
            'components': []
        }
        
        outbound = self.data_sources.get('outbound_connections', {})
        connections = outbound.get('data', {}).get('connections', [])
        
        for conn in connections[:10]:  # 只显示前10个
            external_layer['components'].append({
                'name': conn.get('target'),
                'port': conn.get('port'),
                'protocol': conn.get('protocol'),
                'type': 'external'
            })
        
        if external_layer['components']:
            self.architecture['layers'].append(external_layer)
        
        # 安全发现
        ssh = self.data_sources.get('ssh_security', {})
        ssh_data = ssh.get('data', {})
        
        if ssh_data.get('failed_logins', 0) > 0:
            self.architecture['security_findings'].append({
                'severity': 'high',
                'type': 'ssh_brute_force',
                'description': f"检测到{ssh_data['failed_logins']}次SSH失败登录",
                'attackers': [a[0] for a in ssh_data.get('top_attackers', [])[:5]]
            })
        
        # 数据源完整性评估
        self.architecture['data_coverage'] = self._assess_data_coverage()
    
    def _summarize_data_sources(self) -> Dict:
        """总结数据源覆盖情况"""
        summary = {}
        
        for name, data in self.data_sources.items():
            if data:
                data_size = len(str(data))
                summary[name] = {
                    'available': True,
                    'data_points': self._count_data_points(data)
                }
            else:
                summary[name] = {
                    'available': False,
                    'data_points': 0
                }
        
        return summary
    
    def _count_data_points(self, data: Any, depth: int = 0) -> int:
        """计算数据点数"""
        if depth > 10:
            return 1
        
        if isinstance(data, dict):
            return sum(self._count_data_points(v, depth+1) for v in data.values()) + 1
        elif isinstance(data, list):
            return min(len(data), 100)
        elif isinstance(data, (int, float, str)):
            return 1
        
        return 0
    
    def _assess_data_coverage(self) -> Dict:
        """评估数据覆盖完整性"""
        coverage = {
            'network': False,
            'web_config': False,
            'access_log': False,
            'backend': False,
            'ssh': False,
            'startup': False,
            'overall_score': 0
        }
        
        if self.data_sources.get('network', {}):
            coverage['network'] = True
        if self.data_sources.get('web_proxy', {}).get('data', {}).get('proxies'):
            coverage['web_config'] = True
        if self.data_sources.get('access_log', {}).get('data', {}).get('total_requests', 0) > 0:
            coverage['access_log'] = True
        if self.data_sources.get('backend_services', {}).get('data', {}).get('services'):
            coverage['backend'] = True
        if self.data_sources.get('ssh_security', {}).get('data', {}).get('failed_logins', 0) >= 0:
            coverage['ssh'] = True
        if self.data_sources.get('startup_items', {}).get('data', {}).get('items'):
            coverage['startup'] = True
        
        coverage['overall_score'] = sum(coverage.values()) / 6 * 100
        
        return coverage
    
    def generate_architecture_diagram(self) -> str:
        """生成架构图ASCII"""
        lines = []
        lines.append("")
        lines.append("【完整服务架构图】")
        lines.append("=" * 70)
        
        for layer in self.architecture.get('layers', []):
            layer_num = layer.get('layer', 0)
            layer_name = layer.get('name', '')
            layer_type = layer.get('type', '')
            
            lines.append(f"\n{'─' * 70}")
            lines.append(f"Layer {layer_num}: {layer_name} [{layer_type}]")
            lines.append(f"{'─' * 70}")
            
            components = layer.get('components', [])
            if not components:
                lines.append("  (无组件)")
            else:
                for comp in components:
                    name = comp.get('name', 'Unknown')
                    comp_type = comp.get('type', '')
                    
                    lines.append(f"\n  ├── {name}")
                    
                    if comp_type == 'web_server':
                        listen = comp.get('listen', 'N/A')
                        domains = comp.get('domains', [])
                        lines.append(f"  │   Port: {listen}")
                        if domains:
                            lines.append(f"  │   Domains: {', '.join(domains[:3])}")
                    
                    elif comp_type == 'backend_service':
                        port = comp.get('port', 'N/A')
                        config = comp.get('config', 'N/A')
                        lines.append(f"  │   Port: {port}")
                        lines.append(f"  │   Config: {config[:40]}")
                    
                    elif comp_type == 'tunnel_service':
                        cmd = comp.get('command', '')
                        source = comp.get('source', '')
                        lines.append(f"  │   Command: {cmd}")
                        lines.append(f"  │   Source: {source[:40]}")
                    
                    elif comp_type == 'database':
                        port = comp.get('port', 'N/A')
                        status = comp.get('status', 'unknown')
                        lines.append(f"  │   Port: {port}")
                        lines.append(f"  │   Status: {status}")
                    
                    elif comp_type == 'external':
                        port = comp.get('port', 'N/A')
                        protocol = comp.get('protocol', 'TCP')
                        lines.append(f"  │   → {name}:{port} ({protocol})")
        
        # 安全发现
        security_findings = self.architecture.get('security_findings', [])
        if security_findings:
            lines.append(f"\n{'─' * 70}")
            lines.append("【安全发现】")
            lines.append(f"{'─' * 70}")
            
            for finding in security_findings:
                severity = finding.get('severity', 'info')
                severity_icon = "🔴" if severity == 'high' else "🟡"
                lines.append(f"\n  {severity_icon} {finding.get('description', '')}")
        
        lines.append("\n" + "=" * 70)
        
        # 数据覆盖评估
        coverage = self.architecture.get('data_coverage', {})
        if coverage:
            score = coverage.get('overall_score', 0)
            lines.append(f"\n数据覆盖完整性: {score:.0f}%")
            lines.append("可用数据源:")
            for key, val in coverage.items():
                if key != 'overall_score':
                    status = "✓" if val else "✗"
                    lines.append(f"  {status} {key}")
        
        return "\n".join(lines)


def correlate_all_data(**kwargs) -> Dict[str, Any]:
    """便捷函数：关联分析所有数据"""
    engine = CorrelationEngine()
    return engine.analyze(**kwargs)
