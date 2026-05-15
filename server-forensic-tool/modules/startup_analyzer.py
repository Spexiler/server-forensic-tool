#!/usr/bin/env python3
"""
程序启动项扫描模块 v2.0
扫描systemd、cron、supervisor等自启动配置
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
from .utils import safe_execute


class StartupAnalyzer:
    """程序启动项分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.warnings = []
        self.startup_items = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行启动项分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"启动项分析: {msg}")
        
        return {
            'data': {
                'items': self.startup_items,
                'by_source': self._group_by_source(),
                'summary': self._generate_summary()
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._scan_systemd()
        self._scan_cron()
        self._scan_supervisor()
        self._scan_init_scripts()
        self._scan_runit()
        self._scan_rc_local()
    
    def _add_item(self, name: str, command: str, source: str, details: Dict = None):
        """添加启动项"""
        self.startup_items.append({
            'name': name,
            'command': command,
            'source': source,
            'details': details or {},
            'type': self._identify_service_type(command)
        })
    
    def _identify_service_type(self, command: str) -> str:
        """识别服务类型"""
        command_lower = command.lower()
        
        # 隧道/代理工具
        tunnel_keywords = ['gost', 'frp', 'xray', 'v2ray', 'shadowsocks', 'ss-', 
                         'brook', 'trojan', 'naiveproxy', 'relay']
        for kw in tunnel_keywords:
            if kw in command_lower:
                return f'隧道/代理({kw})'
        
        # Web服务
        if any(x in command_lower for x in ['nginx', 'apache', 'httpd', 'lighttpd']):
            return 'Web服务器'
        
        # 数据库
        if any(x in command_lower for x in ['mysql', 'mariadb', 'postgres', 'mongodb', 'redis']):
            return '数据库'
        
        # SSH
        if 'ssh' in command_lower:
            return 'SSH服务'
        
        # 容器
        if any(x in command_lower for x in ['docker', 'containerd', 'podman']):
            return '容器平台'
        
        # 监控
        if any(x in command_lower for x in ['zabbix', 'prometheus', 'grafana', 'monitor']):
            return '监控系统'
        
        return '其他'
    
    def _scan_systemd(self):
        """扫描systemd服务"""
        systemd_dirs = [
            Path('/etc/systemd/system/'),
            Path('/lib/systemd/system/'),
            Path('/usr/lib/systemd/system/'),
            Path('/run/systemd/system/'),
        ]
        
        # 扫描目标目录
        for pattern in ['*.service']:
            for systemd_dir in systemd_dirs:
                if systemd_dir.exists():
                    for service_file in systemd_dir.glob(pattern):
                        try:
                            self._parse_systemd_service(service_file)
                        except Exception:
                            continue
        
        # 扫描目标目录下的systemd文件
        for pattern in ['*.service', 'system/**/*.service']:
            for service_file in self.target_dir.rglob(pattern):
                try:
                    self._parse_systemd_service(service_file)
                except Exception:
                    continue
    
    def _parse_systemd_service(self, service_file: Path):
        """解析systemd服务文件"""
        try:
            content = service_file.read_text(errors='ignore')
            
            # 提取服务名
            service_name = service_file.stem
            
            # 检查是否启用
            enabled = False
            if 'Enabled=' in content or '[Install]' in content:
                enabled = True
            
            # 提取ExecStart
            exec_start = None
            for line in content.split('\n'):
                if line.startswith('ExecStart='):
                    exec_start = line.split('=', 1)[1].strip()
                    break
            
            if exec_start:
                self._add_item(
                    name=service_name,
                    command=exec_start,
                    source=f'systemd: {service_file}',
                    details={
                        'enabled': enabled,
                        'type': 'systemd',
                        'file': str(service_file)
                    }
                )
        except Exception:
            pass
    
    def _scan_cron(self):
        """扫描cron定时任务"""
        cron_dirs = [
            Path('/etc/cron.d/'),
            Path('/etc/cron.daily/'),
            Path('/etc/cron.hourly/'),
            Path('/etc/cron.weekly/'),
            Path('/etc/cron.monthly/'),
            Path('/var/spool/cron/crontabs/'),
            Path('/etc/crontab'),
        ]
        
        # 扫描系统cron
        for cron_dir in cron_dirs:
            if cron_dir.exists():
                if cron_dir.is_file():
                    self._parse_crontab(cron_dir)
                else:
                    for cron_file in cron_dir.glob('*'):
                        if cron_file.is_file():
                            self._parse_cron_file(cron_file)
        
        # 扫描目标目录
        for pattern in ['cron*', '**/crontab*']:
            for cron_file in self.target_dir.rglob(pattern):
                self._parse_cron_file(cron_file)
    
    def _parse_crontab(self, crontab_file: Path):
        """解析crontab文件"""
        try:
            content = crontab_file.read_text(errors='ignore')
            
            for line in content.split('\n'):
                line = line.strip()
                
                # 跳过注释和空行
                if not line or line.startswith('#'):
                    continue
                
                # 跳过环境变量
                if '=' in line and not line.startswith('*') and not line[0].isdigit():
                    continue
                
                # 解析cron行
                parts = line.split()
                if len(parts) >= 6:
                    schedule = ' '.join(parts[:5])
                    command = ' '.join(parts[5:])
                    
                    self._add_item(
                        name=crontab_file.name,
                        command=command,
                        source=f'cron: {crontab_file}',
                        details={
                            'schedule': schedule,
                            'type': 'cron'
                        }
                    )
        except Exception:
            pass
    
    def _parse_cron_file(self, cron_file: Path):
        """解析cron文件"""
        self._parse_crontab(cron_file)
    
    def _scan_supervisor(self):
        """扫描supervisor配置"""
        supervisor_dirs = [
            Path('/etc/supervisor/conf.d/'),
            Path('/etc/supervisord.conf.d/'),
        ]
        
        conf_patterns = ['*.conf', '*.ini']
        
        for supervisor_dir in supervisor_dirs:
            if supervisor_dir.exists():
                for pattern in conf_patterns:
                    for conf_file in supervisor_dir.glob(pattern):
                        self._parse_supervisor_conf(conf_file)
        
        # 扫描目标目录
        for pattern in ['supervisor*.conf', '**/supervisor/**/*.conf']:
            for conf_file in self.target_dir.rglob(pattern):
                self._parse_supervisor_conf(conf_file)
    
    def _parse_supervisor_conf(self, conf_file: Path):
        """解析supervisor配置"""
        try:
            content = conf_file.read_text(errors='ignore')
            
            # 提取program段
            program_match = re.search(r'\[program:([^\]]+)\]', content)
            if program_match:
                program_name = program_match.group(1)
                
                # 提取command
                command_match = re.search(r'command\s*=\s*(.+)$', content, re.MULTILINE)
                if command_match:
                    command = command_match.group(1).strip()
                    
                    # 检查是否自动启动
                    autostart = True
                    if re.search(r'autostart\s*=\s*false', content, re.IGNORECASE):
                        autostart = False
                    
                    self._add_item(
                        name=program_name,
                        command=command,
                        source=f'supervisor: {conf_file}',
                        details={
                            'autostart': autostart,
                            'type': 'supervisor'
                        }
                    )
        except Exception:
            pass
    
    def _scan_init_scripts(self):
        """扫描init.d脚本"""
        init_dirs = [
            Path('/etc/init.d/'),
            Path('/etc/rc.d/init.d/'),
        ]
        
        for init_dir in init_dirs:
            if init_dir.exists():
                for init_script in init_dir.glob('*'):
                    if init_script.is_file() and os.access(init_script, os.X_OK):
                        try:
                            content = init_script.read_text(errors='ignore', encoding='utf-8')
                            
                            # 提取启动命令
                            for line in content.split('\n')[:50]:  # 只看开头
                                if line.startswith('DAEMON=') or 'daemon' in line.lower():
                                    match = re.search(r'["\']([^"\']+)["\']', line)
                                    if match:
                                        cmd = match.group(1)
                                        self._add_item(
                                            name=init_script.name,
                                            command=cmd,
                                            source=f'init.d: {init_script}',
                                            details={'type': 'init.d'}
                                        )
                                        break
                        except Exception:
                            continue
        
        # 扫描目标目录
        for pattern in ['init.d/*', '**/init.d/**']:
            for init_script in self.target_dir.rglob(pattern):
                if init_script.is_file():
                    self._parse_init_script(init_script)
    
    def _parse_init_script(self, script_file: Path):
        """解析init脚本"""
        try:
            content = script_file.read_text(errors='ignore', encoding='utf-8')
            
            for line in content.split('\n')[:50]:
                if 'daemon' in line.lower():
                    match = re.search(r'["\']([^"\']+)["\']', line)
                    if match:
                        cmd = match.group(1)
                        self._add_item(
                            name=script_file.name,
                            command=cmd,
                            source=f'init: {script_file}',
                            details={'type': 'init'}
                        )
                        break
        except Exception:
            pass
    
    def _scan_runit(self):
        """扫描runit服务"""
        runit_dirs = [
            Path('/etc/sv/'),
            Path('/var/service/'),
            Path('/var/sv/'),
        ]
        
        for runit_dir in runit_dirs:
            if runit_dir.exists():
                for service_dir in runit_dir.iterdir():
                    if service_dir.is_dir():
                        run_file = service_dir / 'run'
                        if run_file.exists():
                            try:
                                content = run_file.read_text(errors='ignore')
                                first_line = content.split('\n')[0] if content else ''
                                
                                if first_line and not first_line.startswith('#'):
                                    self._add_item(
                                        name=service_dir.name,
                                        command=first_line,
                                        source=f'runit: {run_file}',
                                        details={'type': 'runit'}
                                    )
                            except Exception:
                                continue
        
        # 扫描目标目录
        for pattern in ['**/run']:
            for run_file in self.target_dir.rglob(pattern):
                if run_file.name == 'run' and run_file.parent.name != '__pycache__':
                    self._parse_runit_run(run_file)
    
    def _parse_runit_run(self, run_file: Path):
        """解析runit run文件"""
        try:
            content = run_file.read_text(errors='ignore')
            first_line = content.split('\n')[0] if content else ''
            
            if first_line and not first_line.startswith('#'):
                self._add_item(
                    name=run_file.parent.name,
                    command=first_line,
                    source=f'runit: {run_file}',
                    details={'type': 'runit'}
                )
        except Exception:
            pass
    
    def _scan_rc_local(self):
        """扫描rc.local"""
        rc_local_paths = [
            Path('/etc/rc.local'),
            Path('/etc/rc.d/rc.local'),
        ]
        
        for rc_local in rc_local_paths:
            if rc_local.exists():
                try:
                    content = rc_local.read_text(errors='ignore')
                    
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # 这是要执行的命令
                            if line.startswith('/') or line.startswith('bash') or line.startswith('sh'):
                                self._add_item(
                                    name=f'rc.local:{len(self.startup_items)}',
                                    command=line,
                                    source=f'rc.local: {rc_local}',
                                    details={'type': 'rc.local'}
                                )
                except Exception:
                    pass
        
        # 扫描目标目录
        for pattern in ['rc.local*', '**/rc.local*']:
            for rc_file in self.target_dir.rglob(pattern):
                self._parse_rc_local(rc_file)
    
    def _parse_rc_local(self, rc_file: Path):
        """解析rc.local文件"""
        try:
            content = rc_file.read_text(errors='ignore')
            
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.startswith('/') or line.startswith('bash'):
                        self._add_item(
                            name=f'rc: {rc_file.name}:{len(self.startup_items)}',
                            command=line,
                            source=f'rc.local: {rc_file}',
                            details={'type': 'rc.local'}
                        )
        except Exception:
            pass
    
    def _group_by_source(self) -> Dict[str, List[Dict]]:
        """按来源分组"""
        grouped = defaultdict(list)
        
        for item in self.startup_items:
            source_type = item['source'].split(':')[0]
            grouped[source_type].append(item)
        
        return dict(grouped)
    
    def _generate_summary(self) -> Dict:
        """生成摘要"""
        summary = {
            'total': len(self.startup_items),
            'by_type': defaultdict(int),
            'tunnel_services': [],
        }
        
        for item in self.startup_items:
            summary['by_type'][item['type']] += 1
            
            # 特别标记隧道服务
            if '隧道' in item.get('type', '') or any(x in item.get('command', '').lower() 
                for x in ['gost', 'frp', 'xray', 'v2ray', 'rel_node']):
                summary['tunnel_services'].append({
                    'name': item['name'],
                    'command': item['command'],
                    'source': item['source']
                })
        
        summary['by_type'] = dict(summary['by_type'])
        return summary


def analyze_startup_items(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：分析启动项"""
    analyzer = StartupAnalyzer(target_dir, timeout)
    return analyzer.analyze()
