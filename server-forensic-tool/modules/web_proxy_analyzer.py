#!/usr/bin/env python3
"""
Web服务器配置解析模块 v2.0
用于解析Nginx/Apache反向代理配置，生成完整的服务链路拓扑
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from .utils import safe_execute


class WebProxyAnalyzer:
    """Web反向代理配置分析器"""
    
    # Nginx配置目录
    NGINX_CONFIG_DIRS = [
        '/etc/nginx/conf.d/',
        '/etc/nginx/sites-enabled/',
        '/etc/nginx/sites-available/',
        '/usr/local/nginx/conf/',
        '/www/server/panel/vhost/nginx/',
        '/etc/apache2/sites-enabled/',
        '/etc/apache2/sites-available/',
        '/etc/httpd/conf.d/',
        'C:/nginx/conf/',
        'D:/nginx/conf/',
        'C:/wnmp/nginx/conf/',
        'D:/wnmp/nginx/conf/',
    ]
    
    # Apache配置目录
    APACHE_CONFIG_DIRS = [
        '/etc/apache2/sites-enabled/',
        '/etc/apache2/sites-available/',
        '/etc/httpd/conf.d/',
        'C:/apache/conf/extra/',
        'D:/apache/conf/extra/',
    ]
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.proxies = []
        self.upstreams = defaultdict(dict)
        self.warnings = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行完整的反向代理配置分析"""
        # 使用安全执行包装
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"反向代理分析: {msg}")
        
        return {
            'data': {
                'proxies': self.proxies,
                'upstreams': dict(self.upstreams),
                'topology': self._build_topology()
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._scan_nginx_configs()
        self._scan_apache_configs()
        self._extract_upstreams()
    
    def _scan_nginx_configs(self):
        """扫描Nginx配置"""
        # 查找配置文件
        config_files = []
        
        # 扫描目标目录
        for pattern in ['*.conf', 'nginx.conf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描常见配置目录
        for config_dir in self.NGINX_CONFIG_DIRS:
            config_path = Path(config_dir)
            if config_path.exists():
                for pattern in ['*.conf']:
                    config_files.extend(config_path.glob(pattern))
        
        # 去重
        config_files = list(set(config_files))
        
        for config_file in config_files:
            try:
                content = config_file.read_text(errors='ignore')
                self._parse_nginx_file(config_file, content)
            except Exception as e:
                self.warnings.append(f"解析Nginx配置失败 {config_file}: {e}")
    
    def _parse_nginx_file(self, file_path: Path, content: str):
        """解析单个Nginx配置文件"""
        # 提取server块
        server_blocks = self._extract_nginx_server_blocks(content)
        
        for server_content, server_start in server_blocks:
            proxy_info = self._parse_nginx_server(server_content, file_path)
            if proxy_info:
                self.proxies.append(proxy_info)
        
        # 提取upstream块
        self._extract_nginx_upstreams(content, file_path)
    
    def _extract_nginx_server_blocks(self, content: str) -> List[tuple]:
        """提取Nginx server块"""
        blocks = []
        brace_count = 0
        server_start = 0
        in_server = False
        server_content_lines = []
        
        for line_num, line in enumerate(content.split('\n')):
            stripped = line.strip()
            
            # 跳过注释
            if stripped.startswith('#'):
                continue
            
            if 'server' in stripped and '{' in stripped and not in_server:
                in_server = True
                server_start = line_num
                server_content_lines = [line]
                brace_count = line.count('{') - line.count('}')
            elif in_server:
                server_content_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count == 0:
                    blocks.append(('\n'.join(server_content_lines), server_start))
                    in_server = False
                    server_content_lines = []
        
        return blocks
    
    def _extract_nginx_upstreams(self, content: str, file_path: Path):
        """提取Nginx upstream块"""
        upstream_pattern = r'upstream\s+(\S+)\s*\{([^}]+)\}'
        matches = re.finditer(upstream_pattern, content, re.DOTALL)
        
        for match in matches:
            upstream_name = match.group(1)
            upstream_content = match.group(2)
            
            # 提取服务器列表
            servers = []
            server_pattern = r'server\s+([^;]+);'
            for server_match in re.finditer(server_pattern, upstream_content):
                server_def = server_match.group(1).strip()
                servers.append(server_def)
            
            self.upstreams[upstream_name] = {
                'servers': servers,
                'file': str(file_path)
            }
    
    def _parse_nginx_server(self, server_content: str, file_path: Path) -> Optional[Dict]:
        """解析Nginx server块内容"""
        info = {
            'type': 'nginx',
            'config_file': str(file_path),
            'server_name': [],
            'listen_port': None,
            'locations': [],
            'upstream': []
        }
        
        # 提取server_name
        server_names = re.findall(r'server_name\s+([^;]+);', server_content)
        if server_names:
            info['server_name'] = [n.strip() for n in server_names[0].split()]
        
        # 提取listen端口
        listen_match = re.search(r'listen\s+(\d+|[\w:]+)\s*(?:default_server)?', server_content)
        if listen_match:
            info['listen_port'] = listen_match.group(1)
        
        # 提取location块
        locations = self._extract_nginx_locations(server_content)
        info['locations'] = locations
        
        # 提取proxy_pass
        proxy_passes = re.findall(r'proxy_pass\s+([^;]+);', server_content)
        for proxy_pass in proxy_passes:
            info['upstream'].append(proxy_pass.strip())
        
        # 提取fastcgi_pass
        fastcgi_passes = re.findall(r'fastcgi_pass\s+([^;]+);', server_content)
        for fastcgi in fastcgi_passes:
            info['upstream'].append(f'fastcgi://{fastcgi.strip()}')
        
        # 如果没有server_name，使用监听端口作为标识
        if not info['server_name']:
            info['server_name'] = [f'*:{info["listen_port"]}']
        
        return info if (info['listen_port'] or info['upstream']) else None
    
    def _extract_nginx_locations(self, server_content: str) -> List[Dict]:
        """提取Nginx location块"""
        locations = []
        location_pattern = r'location\s+(\S+)\s*(?:\(.*?\))?\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(location_pattern, server_content):
            path = match.group(1)
            location_content = match.group(2)
            
            loc_info = {
                'path': path,
                'proxy_pass': None,
                'root': None,
                'fastcgi_pass': None,
                'static_files': False
            }
            
            # 提取proxy_pass
            proxy = re.search(r'proxy_pass\s+([^;]+);', location_content)
            if proxy:
                loc_info['proxy_pass'] = proxy.group(1).strip()
            
            # 提取root
            root = re.search(r'root\s+([^;]+);', location_content)
            if root:
                loc_info['root'] = root.group(1).strip()
            
            # 提取fastcgi_pass
            fastcgi = re.search(r'fastcgi_pass\s+([^;]+);', location_content)
            if fastcgi:
                loc_info['fastcgi_pass'] = fastcgi.group(1).strip()
            
            locations.append(loc_info)
        
        return locations
    
    def _scan_apache_configs(self):
        """扫描Apache配置"""
        config_files = []
        
        # 扫描目标目录
        for pattern in ['*.conf', 'httpd.conf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描常见配置目录
        for config_dir in self.APACHE_CONFIG_DIRS:
            config_path = Path(config_dir)
            if config_path.exists():
                for pattern in ['*.conf']:
                    config_files.extend(config_path.glob(pattern))
        
        # 去重
        config_files = list(set(config_files))
        
        for config_file in config_files:
            try:
                content = config_file.read_text(errors='ignore')
                self._parse_apache_file(config_file, content)
            except Exception as e:
                self.warnings.append(f"解析Apache配置失败 {config_file}: {e}")
    
    def _parse_apache_file(self, file_path: Path, content: str):
        """解析Apache配置文件"""
        # 提取VirtualHost块
        vhost_pattern = r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>'
        matches = re.finditer(vhost_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            vhost_addr = match.group(1).strip()
            vhost_content = match.group(2)
            
            proxy_info = self._parse_apache_vhost(vhost_content, file_path, vhost_addr)
            if proxy_info:
                self.proxies.append(proxy_info)
    
    def _parse_apache_vhost(self, vhost_content: str, file_path: Path, vhost_addr: str) -> Optional[Dict]:
        """解析Apache VirtualHost"""
        info = {
            'type': 'apache',
            'config_file': str(file_path),
            'server_name': [],
            'listen_port': self._extract_apache_port(vhost_addr),
            'proxy_rules': [],
            'locations': []
        }
        
        # 提取ServerName
        server_names = re.findall(r'ServerName\s+(\S+)', vhost_content, re.IGNORECASE)
        info['server_name'] = server_names
        
        # 提取ProxyPass和ProxyPassReverse
        proxy_pattern = r'ProxyPass\s+/([^"]+)\s+([^"]+)'
        for match in re.finditer(proxy_pattern, vhost_content):
            path = match.group(1)
            target = match.group(2)
            info['proxy_rules'].append({
                'path': f'/{path}',
                'target': target
            })
        
        # 提取ProxyPassReverse
        reverse_pattern = r'ProxyPassReverse\s+/([^"]+)\s+([^"]+)'
        for match in re.finditer(reverse_pattern, vhost_content):
            path = match.group(1)
            target = match.group(2)
            info['proxy_rules'].append({
                'path': f'/{path} (反向)',
                'target': target
            })
        
        return info if (info['listen_port'] or info['proxy_rules']) else None
    
    def _extract_apache_port(self, vhost_addr: str) -> Optional[str]:
        """从VirtualHost地址提取端口"""
        match = re.search(r':(\d+)', vhost_addr)
        return match.group(1) if match else None
    
    def _build_topology(self) -> List[Dict]:
        """构建服务拓扑图"""
        topology = []
        
        for proxy in self.proxies:
            entry = {
                'layer': 'entry',
                'type': proxy['type'].upper(),
                'listen': proxy.get('listen_port', 'N/A'),
                'server_names': proxy.get('server_name', []),
                'proxy_targets': []
            }
            
            # 添加upstream目标
            for upstream_name in proxy.get('upstream', []):
                if upstream_name in self.upstreams:
                    servers = self.upstreams[upstream_name]['servers']
                    entry['proxy_targets'].extend(servers)
                else:
                    entry['proxy_targets'].append(upstream_name)
            
            # 从location中添加proxy_pass
            if proxy['type'] == 'nginx':
                for loc in proxy.get('locations', []):
                    if loc.get('proxy_pass'):
                        entry['proxy_targets'].append(loc['proxy_pass'])
                    elif loc.get('fastcgi_pass'):
                        entry['proxy_targets'].append(f'fastcgi://{loc["fastcgi_pass"]}')
            
            # 从Apache的proxy_rules添加
            if proxy['type'] == 'apache':
                for rule in proxy.get('proxy_rules', []):
                    entry['proxy_targets'].append(rule['target'])
            
            # 去重
            entry['proxy_targets'] = list(set(entry['proxy_targets']))
            
            topology.append(entry)
        
        return topology
    
    def get_proxy_summary(self) -> str:
        """获取代理配置摘要"""
        lines = []
        lines.append("【反向代理配置摘要】")
        lines.append("-" * 50)
        
        if not self.proxies:
            lines.append("  未发现反向代理配置")
            return "\n".join(lines)
        
        lines.append(f"  发现 {len(self.proxies)} 个代理配置:")
        
        for proxy in self.proxies:
            server_name = proxy.get('server_name', ['未知'])[0]
            port = proxy.get('listen_port', 'N/A')
            lines.append(f"  • {proxy['type'].upper()} - {server_name}:{port}")
        
        return "\n".join(lines)


def analyze_web_proxy(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：分析Web反向代理配置"""
    analyzer = WebProxyAnalyzer(target_dir, timeout)
    return analyzer.analyze()
