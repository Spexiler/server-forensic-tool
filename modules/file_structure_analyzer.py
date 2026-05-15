#!/usr/bin/env python3
"""
文件架构解析模块 v2.0
分析目录结构，识别各目录和文件的角色，构建完整架构图
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from datetime import datetime
from .utils import safe_execute


class DirectoryRole:
    """目录角色识别"""
    
    ROLE_PATTERNS = {
        'web_root': {
            'dirs': ['html', 'public_html', 'www', 'web', 'htdocs', 'wwwroot', 'public', 'static'],
            'files': ['index.html', 'index.htm', 'index.php', 'default.html'],
            'description': 'Web文档根目录'
        },
        'web_app': {
            'dirs': ['app', 'application', 'apps', 'webapp', 'src'],
            'files': ['*.php', '*.py', '*.rb', '*.js', '*.ts'],
            'description': 'Web应用程序'
        },
        'config': {
            'dirs': ['conf', 'config', 'cfg', 'settings', 'etc'],
            'files': ['*.conf', '*.cfg', '*.ini', '*.yaml', '*.yml', '*.json', '*.toml', '.env*'],
            'description': '配置文件目录'
        },
        'log': {
            'dirs': ['log', 'logs', 'var/log', 'logfiles'],
            'files': ['*.log', 'syslog', 'messages', '*.log.*'],
            'description': '日志文件目录'
        },
        'database': {
            'dirs': ['data', 'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb'],
            'files': ['*.sql', '*.db', '*.sqlite', '*.mdb'],
            'description': '数据库文件目录'
        },
        'cache': {
            'dirs': ['cache', 'tmp', 'temp', 'session', 'sessions'],
            'files': ['*.cache', '*.tmp'],
            'description': '缓存和临时文件'
        },
        'static_resource': {
            'dirs': ['static', 'assets', 'css', 'js', 'images', 'media', 'uploads', 'files', 'public/uploads'],
            'files': ['*.css', '*.js', '*.png', '*.jpg', '*.jpeg', '*.gif', '*.svg', '*.ico', '*.woff*'],
            'description': '静态资源目录'
        },
        'backend_service': {
            'dirs': ['api', 'backend', 'server', 'services', 'lib', 'bin', 'scripts'],
            'files': ['*.py', '*.go', '*.java', '*.class', '*.so'],
            'description': '后端服务和库'
        },
        'security': {
            'dirs': ['ssl', 'certs', 'keys', 'security', 'auth'],
            'files': ['*.pem', '*.key', '*.crt', '*.cert', '*.p12', '.htpasswd'],
            'description': '安全相关文件'
        },
        'system': {
            'dirs': ['system', 'sys', 'proc', 'boot', 'dev'],
            'files': ['*.service', '*.socket', '*.target', 'crontab', '*.cron'],
            'description': '系统配置和服务'
        },
        'backup': {
            'dirs': ['backup', 'backups', 'bak', 'archive', 'old'],
            'files': ['*.bak', '*.backup', '*.old', '*.tar*', '*.zip', '*.gz'],
            'description': '备份文件目录'
        },
        'user_content': {
            'dirs': ['uploads', 'user', 'users', 'home', 'var/users'],
            'files': [],
            'description': '用户上传内容'
        },
        'proxy_config': {
            'dirs': ['nginx', 'apache', 'apache2', 'httpd', 'proxy'],
            'files': ['nginx.conf', 'apache2.conf', 'httpd.conf', '*.vhost'],
            'description': 'Web服务器配置'
        },
        'container': {
            'dirs': ['docker', 'containers', '.docker'],
            'files': ['Dockerfile', 'docker-compose.yml', '*.dockerfile'],
            'description': '容器化配置'
        },
        'monitoring': {
            'dirs': ['monitor', 'monitoring', 'metrics', 'stats'],
            'files': ['*.metrics', 'status*'],
            'description': '监控相关'
        }
    }
    
    @classmethod
    def identify_dir_role(cls, dir_name: str, parent_roles: List[str] = None) -> Optional[Dict[str, Any]]:
        """识别目录角色"""
        dir_name_lower = dir_name.lower()
        parent_roles = parent_roles or []
        
        for role_name, patterns in cls.ROLE_PATTERNS.items():
            if dir_name_lower in [d.lower() for d in patterns['dirs']]:
                return {
                    'role': role_name,
                    'description': patterns['description'],
                    'confidence': 'high'
                }
        
        if parent_roles:
            return {
                'role': parent_roles[0],
                'description': cls.ROLE_PATTERNS.get(parent_roles[0], {}).get('description', '子目录'),
                'confidence': 'low'
            }
        
        return None
    
    @classmethod
    def identify_file_role(cls, file_name: str, file_path: str) -> Optional[Dict[str, Any]]:
        """识别文件角色"""
        file_name_lower = file_name.lower()
        path_lower = file_path.lower()
        
        for role_name, patterns in cls.ROLE_PATTERNS.items():
            for pattern in patterns['files']:
                if '*' in pattern:
                    ext = pattern.replace('*.', '.')
                    if file_name_lower.endswith(ext):
                        return {
                            'role': role_name,
                            'description': patterns['description'],
                            'file': file_name
                        }
                elif pattern in path_lower:
                    return {
                        'role': role_name,
                        'description': patterns['description'],
                        'file': file_name
                    }
        
        return None


class FileStructureAnalyzer:
    """文件架构分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 60, max_depth: int = 8):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.max_depth = max_depth
        self.warnings = []
        
        self.structure = {
            'root': str(target_dir),
            'total_files': 0,
            'total_dirs': 0,
            'total_size': 0,
            'max_depth': 0,
            'dir_tree': {},
            'role_distribution': defaultdict(int),
            'dir_roles': {},
            'key_files': [],
            'architecture_layers': [],
            'file_type_stats': defaultdict(int),
            'important_paths': []
        }
    
    def analyze(self) -> Dict[str, Any]:
        """执行文件架构分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"文件架构分析: {msg}")
        
        self.structure['analysis_timestamp'] = datetime.now().isoformat()
        self.structure['warnings'] = self.warnings
        
        return {
            'data': self.structure,
            'warnings': self.warnings,
            'architecture_diagram': self._generate_architecture_diagram(),
            'summary': self._generate_summary()
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._scan_directory()
        self._identify_layers()
        self._find_key_files()
    
    def _scan_directory(self):
        """扫描目录结构"""
        self._scan_recursive(self.target_dir, depth=0, parent_path='')
    
    def _scan_recursive(self, path: Path, depth: int, parent_path: str):
        """递归扫描目录"""
        if depth > self.max_depth:
            return
        
        self.structure['max_depth'] = max(self.structure['max_depth'], depth)
        
        try:
            for item in path.iterdir():
                rel_path = item.relative_to(self.target_dir)
                
                if item.is_dir():
                    self.structure['total_dirs'] += 1
                    
                    dir_role = self._analyze_directory(item, rel_path, depth)
                    if dir_role:
                        self.structure['dir_roles'][str(rel_path)] = dir_role
                        self.structure['role_distribution'][dir_role['role']] += 1
                    
                    self._scan_recursive(item, depth + 1, str(rel_path))
                
                else:
                    self.structure['total_files'] += 1
                    
                    try:
                        size = item.stat().st_size
                        self.structure['total_size'] += size
                    except:
                        size = 0
                    
                    ext = item.suffix.lower()
                    if ext:
                        self.structure['file_type_stats'][ext] += 1
                    
                    file_role = self._analyze_file(item, rel_path)
                    if file_role:
                        self.structure['key_files'].append({
                            'path': str(rel_path),
                            'role': file_role['role'],
                            'size': size,
                            'description': file_role['description']
                        })
        
        except PermissionError:
            self.warnings.append(f"权限不足: {path}")
        except Exception as e:
            pass
    
    def _analyze_directory(self, dir_path: Path, rel_path: Path, depth: int) -> Optional[Dict]:
        """分析目录"""
        dir_name = dir_path.name
        
        parent_roles = []
        if str(rel_path.parent) in self.structure['dir_roles']:
            parent_roles.append(self.structure['dir_roles'][str(rel_path.parent)]['role'])
        
        role_info = DirectoryRole.identify_dir_role(dir_name, parent_roles)
        
        if role_info:
            return role_info
        
        sub_dirs = self._get_sub_dirs(dir_path)
        if sub_dirs:
            for sub_dir in sub_dirs[:5]:
                sub_role = DirectoryRole.identify_dir_role(sub_dir.name, [role_info['role']] if role_info else [])
                if sub_role:
                    return sub_role
        
        return None
    
    def _get_sub_dirs(self, dir_path: Path) -> List[Path]:
        """获取子目录"""
        try:
            return [p for p in dir_path.iterdir() if p.is_dir()]
        except:
            return []
    
    def _analyze_file(self, file_path: Path, rel_path: Path) -> Optional[Dict]:
        """分析文件"""
        return DirectoryRole.identify_file_role(file_path.name, str(rel_path))
    
    def _identify_layers(self):
        """识别架构层次"""
        layers = []
        
        layer_defs = [
            {
                'name': '入口层 (Entry)',
                'indicators': ['www', 'html', 'public', 'public_html', 'htdocs', 'web'],
                'types': ['web_root', 'static_resource']
            },
            {
                'name': '应用层 (Application)',
                'indicators': ['app', 'application', 'src', 'api', 'backend'],
                'types': ['web_app', 'backend_service']
            },
            {
                'name': '配置层 (Configuration)',
                'indicators': ['config', 'conf', 'cfg', 'settings', 'etc'],
                'types': ['config', 'proxy_config']
            },
            {
                'name': '数据层 (Data)',
                'indicators': ['data', 'db', 'database', 'cache', 'session'],
                'types': ['database', 'cache', 'log']
            },
            {
                'name': '安全层 (Security)',
                'indicators': ['ssl', 'certs', 'keys', 'security'],
                'types': ['security']
            },
            {
                'name': '系统层 (System)',
                'indicators': ['system', 'cron', 'systemd', 'init.d'],
                'types': ['system', 'backup']
            }
        ]
        
        for layer_def in layer_defs:
            found_dirs = []
            
            for dir_path, role_info in self.structure['dir_roles'].items():
                if role_info['role'] in layer_def['types']:
                    found_dirs.append({
                        'path': dir_path,
                        'role': role_info['role'],
                        'description': role_info['description']
                    })
            
            if found_dirs:
                layers.append({
                    'name': layer_def['name'],
                    'directories': found_dirs[:5],
                    'count': len(found_dirs)
                })
        
        self.structure['architecture_layers'] = layers
    
    def _find_key_files(self):
        """查找关键文件"""
        key_patterns = {
            'nginx.conf': 'Nginx主配置',
            'apache2.conf': 'Apache主配置',
            'httpd.conf': 'Apache主配置',
            'my.cnf': 'MySQL配置',
            'postgresql.conf': 'PostgreSQL配置',
            'redis.conf': 'Redis配置',
            'mongod.conf': 'MongoDB配置',
            'Dockerfile': 'Docker容器定义',
            'docker-compose.yml': 'Docker编排配置',
            'package.json': 'Node.js依赖配置',
            'requirements.txt': 'Python依赖配置',
            '.env': '环境变量配置',
            '*.service': 'Systemd服务单元',
            '.htaccess': 'Apache重写规则',
            'nginx.conf': 'Nginx配置',
            'v2ray/config.json': 'V2Ray代理配置',
            'gost.yml': 'GOST代理配置'
        }
        
        for pattern, description in key_patterns.items():
            if '*' in pattern:
                ext = pattern.replace('*', '')
                for path in self.target_dir.rglob(f'*{ext}'):
                    rel_path = path.relative_to(self.target_dir)
                    self.structure['important_paths'].append({
                        'path': str(rel_path),
                        'type': description,
                        'size': path.stat().st_size if path.is_file() else 0
                    })
            else:
                for path in self.target_dir.rglob(pattern):
                    rel_path = path.relative_to(self.target_dir)
                    self.structure['important_paths'].append({
                        'path': str(rel_path),
                        'type': description,
                        'size': path.stat().st_size if path.is_file() else 0
                    })
    
    def _generate_architecture_diagram(self) -> str:
        """生成架构图"""
        lines = []
        lines.append("")
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 15 + "📁 文件架构层次结构图" + " " * 23 + "│")
        lines.append("├" + "─" * 68 + "┤")
        
        layers = self.structure.get('architecture_layers', [])
        
        if layers:
            for i, layer in enumerate(layers):
                layer_name = layer['name']
                lines.append(f"│ [{i+1}] {layer_name}")
                
                dirs = layer.get('directories', [])
                if dirs:
                    for d in dirs[:3]:
                        role_desc = d.get('description', d.get('role', ''))
                        path_short = d['path'][:50]
                        lines.append(f"│      📂 {path_short}")
                        lines.append(f"│          └─ {role_desc}")
                
                if layer['count'] > 3:
                    lines.append(f"│      ... 还有 {layer['count'] - 3} 个目录")
                
                if i < len(layers) - 1:
                    lines.append("│      │")
        
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        
        lines.append("【目录角色分布】")
        for role, count in sorted(self.structure['role_distribution'].items(), key=lambda x: -x[1])[:8]:
            desc = DirectoryRole.ROLE_PATTERNS.get(role, {}).get('description', role)
            lines.append(f"  • {desc}: {count} 个目录")
        
        lines.append("")
        lines.append("【关键配置文件】")
        for imp in self.structure.get('important_paths', [])[:8]:
            lines.append(f"  • {imp['path']}: {imp['type']}")
        
        return "\n".join(lines)
    
    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要"""
        return {
            'total_files': self.structure['total_files'],
            'total_dirs': self.structure['total_dirs'],
            'total_size_mb': round(self.structure['total_size'] / (1024 * 1024), 2),
            'max_depth': self.structure['max_depth'],
            'layer_count': len(self.structure['architecture_layers']),
            'key_file_count': len(self.structure['important_paths']),
            'primary_roles': list(dict(
                sorted(self.structure['role_distribution'].items(), key=lambda x: -x[1])
            ).keys())[:5]
        }


def analyze_file_structure(target_dir: str, timeout: int = 60) -> Dict[str, Any]:
    """便捷函数：分析文件架构"""
    analyzer = FileStructureAnalyzer(target_dir, timeout)
    return analyzer.analyze()
