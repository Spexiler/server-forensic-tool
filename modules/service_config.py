#!/usr/bin/env python3
"""
服务配置分析模块
用于识别和分析服务器上的各种服务配置文件
增强版：确保即使未找到配置文件也会继续分析并记录
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any
from .utils import safe_execute


class ServiceConfigAnalyzer:
    """服务配置分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.services = {}
        self.warnings = []
        self.search_results = {}  # 记录搜索结果
    
    def analyze(self) -> Dict[str, Any]:
        """执行完整的服务配置分析"""
        self.services = {
            'web_servers': {},
            'databases': {},
            'middleware': {},
            'init_scripts': [],
            'summary': {
                'web_servers_found': [],
                'databases_found': [],
                'middleware_found': [],
                'init_scripts_count': 0,
                'total_configs_found': 0,
                'search_status': {}
            }
        }
        
        # 分析Web服务器（即使找不到也继续）
        web_result, web_success, web_msg = safe_execute(
            self._find_web_servers, 
            timeout_seconds=self.timeout_seconds
        )
        
        if not web_success:
            self.warnings.append(f"Web服务器分析: {web_msg}")
            self.services['summary']['search_status']['web_servers'] = {
                'status': 'error',
                'message': web_msg
            }
        else:
            # 检查是否找到配置
            if not self.services['web_servers']:
                self.warnings.append("⚠️ 未在目录中发现Web服务器配置（Apache/Nginx）")
                self.services['summary']['search_status']['web_servers'] = {
                    'status': 'not_found',
                    'message': '未发现Web服务器配置文件'
                }
            else:
                found = list(self.services['web_servers'].keys())
                self.services['summary']['web_servers_found'] = found
                self.services['summary']['search_status']['web_servers'] = {
                    'status': 'found',
                    'message': f"发现 {len(found)} 种Web服务器: {', '.join(found)}",
                    'count': len(found)
                }
        
        # 分析数据库（即使找不到也继续）
        db_result, db_success, db_msg = safe_execute(
            self._find_databases, 
            timeout_seconds=self.timeout_seconds
        )
        
        if not db_success:
            self.warnings.append(f"数据库分析: {db_msg}")
            self.services['summary']['search_status']['databases'] = {
                'status': 'error',
                'message': db_msg
            }
        else:
            if not self.services['databases']:
                self.warnings.append("⚠️ 未在目录中发现数据库配置文件（MySQL/PostgreSQL/MongoDB/Redis）")
                self.services['summary']['search_status']['databases'] = {
                    'status': 'not_found',
                    'message': '未发现数据库配置文件'
                }
            else:
                found = list(self.services['databases'].keys())
                self.services['summary']['databases_found'] = found
                self.services['summary']['search_status']['databases'] = {
                    'status': 'found',
                    'message': f"发现 {len(found)} 种数据库: {', '.join(found)}",
                    'count': len(found)
                }
        
        # 分析中间件（即使找不到也继续）
        mw_result, mw_success, mw_msg = safe_execute(
            self._find_middleware, 
            timeout_seconds=self.timeout_seconds
        )
        
        if not mw_success:
            self.warnings.append(f"中间件分析: {mw_msg}")
            self.services['summary']['search_status']['middleware'] = {
                'status': 'error',
                'message': mw_msg
            }
        else:
            if not self.services['middleware']:
                self.services['summary']['search_status']['middleware'] = {
                    'status': 'not_found',
                    'message': '未发现中间件配置文件'
                }
            else:
                found = list(self.services['middleware'].keys())
                self.services['summary']['middleware_found'] = found
                self.services['summary']['search_status']['middleware'] = {
                    'status': 'found',
                    'message': f"发现 {len(found)} 种中间件: {', '.join(found)}",
                    'count': len(found)
                }
        
        # 分析启动脚本（即使找不到也继续）
        init_result, init_success, init_msg = safe_execute(
            self._find_init_scripts, 
            timeout_seconds=self.timeout_seconds
        )
        
        if not init_success:
            self.warnings.append(f"启动脚本分析: {init_msg}")
            self.services['summary']['search_status']['init_scripts'] = {
                'status': 'error',
                'message': init_msg
            }
        else:
            if not self.services['init_scripts']:
                self.services['summary']['search_status']['init_scripts'] = {
                    'status': 'not_found',
                    'message': '未发现服务启动脚本'
                }
            else:
                self.services['summary']['init_scripts_count'] = len(self.services['init_scripts'])
                self.services['summary']['search_status']['init_scripts'] = {
                    'status': 'found',
                    'message': f"发现 {len(self.services['init_scripts'])} 个启动脚本",
                    'count': len(self.services['init_scripts'])
                }
        
        # 计算总配置文件数量
        total = 0
        for v in self.services['summary']['search_status'].values():
            if v.get('status') == 'found':
                total += v.get('count', 0)
        self.services['summary']['total_configs_found'] = total
        
        return {
            'data': self.services,
            'warnings': self.warnings,
            'search_summary': self.services['summary']
        }
    
    def _find_web_servers(self):
        """查找并分析Web服务器配置"""
        web_services = {}
        apache_count = 0
        nginx_count = 0
        
        # Apache配置查找
        apache_configs = self._search_files([
            'httpd.conf', 'apache2.conf', 'apache.conf',
            '*.conf'
        ], ['apache', 'httpd', 'Apache2'])
        
        if apache_configs:
            web_services['apache'] = self._parse_apache_configs(apache_configs)
            apache_count = len(apache_configs)
        
        # Nginx配置查找
        nginx_configs = self._search_files(['nginx.conf', '*.conf'], ['nginx'])
        
        if nginx_configs:
            web_services['nginx'] = self._parse_nginx_configs(nginx_configs)
            nginx_count = len(nginx_configs)
        
        self.services['web_servers'] = web_services
        self.search_results['apache_configs'] = apache_count
        self.search_results['nginx_configs'] = nginx_count
    
    def _parse_apache_configs(self, config_files: List[Path]) -> Dict[str, Any]:
        """解析Apache配置文件"""
        result = {
            'config_files': [],
            'listen_ports': [],
            'virtual_hosts': [],
            'document_roots': []
        }
        
        for config_file in config_files:
            try:
                result['config_files'].append(str(config_file))
                content = config_file.read_text(errors='ignore')
                
                # 提取监听端口
                listen_matches = re.findall(r'Listen\s+([\d.:]+)', content, re.IGNORECASE)
                result['listen_ports'].extend(listen_matches)
                
                # 提取虚拟主机
                vhost_blocks = re.findall(r'<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>', 
                                         content, re.DOTALL | re.IGNORECASE)
                
                for vhost_addr, vhost_content in vhost_blocks:
                    doc_root = re.search(r'DocumentRoot\s+"?([^"\s]+)"?', vhost_content, re.IGNORECASE)
                    server_name = re.search(r'ServerName\s+(\S+)', vhost_content, re.IGNORECASE)
                    
                    result['virtual_hosts'].append({
                        'address': vhost_addr.strip(),
                        'document_root': doc_root.group(1) if doc_root else None,
                        'server_name': server_name.group(1) if server_name else None
                    })
                
                # 提取文档根目录
                doc_roots = re.findall(r'DocumentRoot\s+"?([^"\s]+)"?', content, re.IGNORECASE)
                result['document_roots'].extend(doc_roots)
                
            except Exception:
                continue
        
        # 去重
        result['listen_ports'] = list(set(result['listen_ports']))
        result['document_roots'] = list(set(result['document_roots']))
        
        return result
    
    def _parse_nginx_configs(self, config_files: List[Path]) -> Dict[str, Any]:
        """解析Nginx配置文件"""
        result = {
            'config_files': [],
            'listen_ports': [],
            'server_blocks': [],
            'root_dirs': []
        }
        
        for config_file in config_files:
            try:
                result['config_files'].append(str(config_file))
                content = config_file.read_text(errors='ignore')
                
                # 提取监听端口
                listen_matches = re.findall(r'listen\s+([\d.:]+)', content, re.IGNORECASE)
                result['listen_ports'].extend(listen_matches)
                
                # 提取server块
                server_blocks = re.findall(r'server\s*\{(.*?)\}', content, re.DOTALL)
                
                for server_content in server_blocks:
                    root_dir = re.search(r'root\s+([^;]+);', server_content)
                    server_name = re.search(r'server_name\s+([^;]+);', server_content)
                    
                    result['server_blocks'].append({
                        'root': root_dir.group(1).strip() if root_dir else None,
                        'server_name': server_name.group(1).strip() if server_name else None
                    })
                
                # 提取root目录
                root_dirs = re.findall(r'root\s+([^;]+);', content)
                result['root_dirs'].extend([d.strip() for d in root_dirs])
                
            except Exception:
                continue
        
        # 去重
        result['listen_ports'] = list(set(result['listen_ports']))
        result['root_dirs'] = list(set(result['root_dirs']))
        
        return result
    
    def _find_databases(self):
        """查找数据库配置"""
        databases = {}
        
        # MySQL配置
        mysql_configs = self._search_files(['my.cnf', 'my.ini'], ['mysql'])
        if mysql_configs:
            databases['mysql'] = {
                'config_files': [str(f) for f in mysql_configs]
            }
        
        # PostgreSQL配置
        pg_configs = self._search_files(['postgresql.conf'], ['postgresql'])
        if pg_configs:
            databases['postgresql'] = {
                'config_files': [str(f) for f in pg_configs]
            }
        
        # MongoDB配置
        mongo_configs = self._search_files(['mongod.conf'], ['mongodb'])
        if mongo_configs:
            databases['mongodb'] = {
                'config_files': [str(f) for f in mongo_configs]
            }
        
        # Redis配置
        redis_configs = self._search_files(['redis.conf'], ['redis'])
        if redis_configs:
            databases['redis'] = {
                'config_files': [str(f) for f in redis_configs]
            }
        
        self.services['databases'] = databases
    
    def _find_middleware(self):
        """查找中间件配置"""
        middleware = {}
        
        # Tomcat配置
        tomcat_configs = self._search_files(['server.xml'], ['tomcat'])
        if tomcat_configs:
            middleware['tomcat'] = {
                'config_files': [str(f) for f in tomcat_configs]
            }
        
        self.services['middleware'] = middleware
    
    def _find_init_scripts(self):
        """查找启动脚本"""
        init_scripts = []
        
        # systemd服务
        systemd_files = self._search_files(['*.service'], ['systemd', 'system'])
        if systemd_files:
            init_scripts.extend([str(f) for f in systemd_files])
        
        self.services['init_scripts'] = init_scripts
    
    def _search_files(self, patterns: List[str], keywords: List[str] = None, 
                     max_depth: int = 10, max_files: int = 1000) -> List[Path]:
        """搜索匹配的文件（带限制防止卡死）"""
        found_files = []
        file_count = 0
        
        try:
            for pattern in patterns:
                if file_count >= max_files:
                    break
                
                for item in self.target_dir.rglob(pattern):
                    if file_count >= max_files:
                        break
                    
                    try:
                        rel_path = item.relative_to(self.target_dir)
                        depth = len(rel_path.parts)
                        if depth > max_depth:
                            continue
                    except ValueError:
                        continue
                    
                    found_files.append(item)
                    file_count += 1
        except Exception:
            pass
        
        # 按关键字过滤
        if keywords:
            filtered = []
            for f in found_files:
                path_str = str(f).lower()
                if any(kw.lower() in path_str for kw in keywords):
                    filtered.append(f)
            found_files = filtered
        
        return found_files
    
    def get_search_report(self) -> str:
        """生成搜索结果报告"""
        lines = []
        lines.append("【服务配置搜索结果】")
        lines.append("-" * 40)
        
        summary = self.services.get('summary', {})
        status = summary.get('search_status', {})
        
        for service_type, info in status.items():
            status_icon = "✓" if info.get('status') == 'found' else "✗"
            lines.append(f"{status_icon} {service_type}: {info.get('message', 'Unknown')}")
        
        lines.append("")
        lines.append(f"总共发现配置文件数: {summary.get('total_configs_found', 0)}")
        
        return "\n".join(lines)
