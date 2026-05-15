#!/usr/bin/env python3
"""
日志文件语义标注模块 v2.0
内置日志文件字典，自动标注日志类型和用途
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import safe_execute


class LogFileAnalyzer:
    """日志文件分析器"""
    
    # 内置日志文件语义字典
    LOG_DICTIONARY = {
        # 认证相关
        'auth.log': {
            'category': '认证',
            'description': '用户认证日志（SSH、sudo等）',
            'severity': 'high',
            'keywords': ['sshd', 'sudo', 'authentication', 'login', 'failed password']
        },
        'auth.log.gz': {
            'category': '认证',
            'description': '历史认证日志（压缩）',
            'severity': 'high',
            'keywords': ['sshd', 'sudo', 'authentication']
        },
        'btmp': {
            'category': '认证-失败',
            'description': '失败登录记录',
            'severity': 'high',
            'keywords': ['failed login', 'wrong password']
        },
        'wtmp': {
            'category': '认证-登录',
            'description': '成功登录记录',
            'severity': 'medium',
            'keywords': ['login', 'logout', 'session']
        },
        'lastlog': {
            'category': '认证-历史',
            'description': '用户最后登录时间',
            'severity': 'low',
            'keywords': []
        },
        
        # 系统日志
        'syslog': {
            'category': '系统',
            'description': '系统日志，涵盖各种系统事件',
            'severity': 'medium',
            'keywords': ['kernel', 'systemd', 'network', 'service']
        },
        'messages': {
            'category': '系统',
            'description': '通用系统日志',
            'severity': 'medium',
            'keywords': ['kernel', 'network', 'hardware']
        },
        'kern.log': {
            'category': '内核',
            'description': '内核日志',
            'severity': 'medium',
            'keywords': ['kernel', 'hardware', 'driver']
        },
        'dmesg': {
            'category': '内核-启动',
            'description': '启动时的内核消息',
            'severity': 'low',
            'keywords': ['kernel', 'boot']
        },
        
        # 应用日志
        'cron': {
            'category': '定时任务',
            'description': '定时任务执行日志',
            'severity': 'low',
            'keywords': ['cron', 'crontab', 'scheduled']
        },
        'cron.log': {
            'category': '定时任务',
            'description': '定时任务日志',
            'severity': 'low',
            'keywords': ['cron', 'task']
        },
        'daemon.log': {
            'category': '守护进程',
            'description': '守护进程日志',
            'severity': 'low',
            'keywords': ['daemon', 'service']
        },
        
        # 安全日志
        'ufw.log': {
            'category': '防火墙',
            'description': 'UFW防火墙日志',
            'severity': 'high',
            'keywords': ['UFW', 'iptables', 'FIREWALL', 'IN=', 'OUT=']
        },
        'iptables.log': {
            'category': '防火墙',
            'description': 'iptables日志',
            'severity': 'high',
            'keywords': ['iptables', 'DPT=', 'SPT=']
        },
        'fail2ban.log': {
            'category': '安全-防护',
            'description': 'fail2ban防护日志',
            'severity': 'high',
            'keywords': ['fail2ban', 'ban', 'unban', 'already banned']
        },
        
        # Web服务器
        'access.log': {
            'category': 'Web-访问',
            'description': 'Web访问日志',
            'severity': 'medium',
            'keywords': ['GET', 'POST', 'HTTP']
        },
        'error.log': {
            'category': 'Web-错误',
            'description': 'Web服务器错误日志',
            'severity': 'high',
            'keywords': ['error', 'warning', 'failed']
        },
        'nginx/access.log': {
            'category': 'Web-访问',
            'description': 'Nginx访问日志',
            'severity': 'medium',
            'keywords': ['GET', 'POST', 'HTTP']
        },
        'nginx/error.log': {
            'category': 'Web-错误',
            'description': 'Nginx错误日志',
            'severity': 'high',
            'keywords': ['error', 'upstream']
        },
        'apache2/access.log': {
            'category': 'Web-访问',
            'description': 'Apache访问日志',
            'severity': 'medium',
            'keywords': ['GET', 'POST', 'HTTP']
        },
        'apache2/error.log': {
            'category': 'Web-错误',
            'description': 'Apache错误日志',
            'severity': 'high',
            'keywords': ['error', 'client']
        },
        
        # 数据库
        'mysql/error.log': {
            'category': '数据库-错误',
            'description': 'MySQL错误日志',
            'severity': 'high',
            'keywords': ['ERROR', 'InnoDB', 'MySQL']
        },
        'mysql/slow.log': {
            'category': '数据库-慢查询',
            'description': 'MySQL慢查询日志',
            'severity': 'medium',
            'keywords': ['Query_time', 'SELECT', 'LOCK']
        },
        'postgresql/postgresql.log': {
            'category': '数据库-错误',
            'description': 'PostgreSQL日志',
            'severity': 'high',
            'keywords': ['ERROR', 'FATAL', 'LOG']
        },
        
        # Docker
        'docker.log': {
            'category': '容器',
            'description': 'Docker守护进程日志',
            'severity': 'medium',
            'keywords': ['docker', 'container']
        },
        'containers.log': {
            'category': '容器',
            'description': '容器日志',
            'severity': 'medium',
            'keywords': ['container', 'image']
        },
        
        # 应用特定
        'supervisor.log': {
            'category': '进程管理',
            'description': 'Supervisor日志',
            'severity': 'medium',
            'keywords': ['supervisor', 'spawned', 'exit']
        },
        'supervisord.log': {
            'category': '进程管理',
            'description': 'Supervisor守护进程日志',
            'severity': 'medium',
            'keywords': ['supervisord', 'started']
        },
    }
    
    # 异常大小阈值 (MB)
    SIZE_THRESHOLDS = {
        'btmp': 10,           # 失败登录记录超过10MB异常
        'auth.log': 50,      # 认证日志超过50MB异常
        'syslog': 100,       # 系统日志超过100MB异常
        'access.log': 200,   # 访问日志超过200MB异常
        'error.log': 50,     # 错误日志超过50MB异常
        'mysql/error.log': 50,
        'default': 100        # 默认100MB
    }
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.warnings = []
        self.log_files = []
        self.anomalies = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行日志文件分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"日志文件分析: {msg}")
        
        return {
            'data': {
                'files': self.log_files,
                'anomalies': self.anomalies,
                'summary': self._generate_summary()
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        # 扫描常见日志目录
        log_dirs = [
            Path('/var/log/'),
            Path('/var/log/nginx/'),
            Path('/var/log/apache2/'),
            Path('/var/log/httpd/'),
            Path('/var/log/mysql/'),
            Path('/var/log/postgresql/'),
            Path('/var/log/docker/'),
        ]
        
        # 扫描目标目录
        for log_dir in log_dirs:
            if log_dir.exists():
                self._scan_log_directory(log_dir)
        
        # 扫描目标目录下的所有日志
        for pattern in ['*.log', '*.log.*', '*access*', '*error*', '*btmp*']:
            for log_file in self.target_dir.rglob(pattern):
                self._analyze_log_file(log_file)
        
        # 检测异常
        self._detect_anomalies()
    
    def _scan_log_directory(self, log_dir: Path):
        """扫描日志目录"""
        try:
            for item in log_dir.iterdir():
                if item.is_file():
                    self._analyze_log_file(item)
                elif item.is_dir():
                    # 递归扫描子目录
                    for sub_item in item.iterdir():
                        if sub_item.is_file():
                            self._analyze_log_file(sub_item)
        except PermissionError:
            pass
        except Exception:
            pass
    
    def _analyze_log_file(self, log_file: Path):
        """分析单个日志文件"""
        try:
            # 获取文件信息
            stat = log_file.stat()
            size_mb = stat.st_size / (1024 * 1024)
            
            # 获取语义标注
            annotation = self._get_annotation(log_file)
            
            log_info = {
                'path': str(log_file),
                'name': log_file.name,
                'size_mb': round(size_mb, 2),
                'size_bytes': stat.st_size,
                'modified': stat.st_mtime,
                'category': annotation.get('category', '其他'),
                'description': annotation.get('description', '未分类日志'),
                'severity': annotation.get('severity', 'low'),
                'keywords': annotation.get('keywords', []),
                'is_compressed': str(log_file).endswith('.gz')
            }
            
            self.log_files.append(log_info)
            
        except Exception:
            pass
    
    def _get_annotation(self, log_file: Path) -> Dict:
        """获取日志文件语义标注"""
        filename = log_file.name
        relative_path = str(log_file.relative_to(log_file.anchor) if hasattr(log_file, 'anchor') else log_file)
        
        # 精确匹配
        if filename in self.LOG_DICTIONARY:
            return self.LOG_DICTIONARY[filename]
        
        # 路径匹配
        for key, value in self.LOG_DICTIONARY.items():
            if key in relative_path or key in str(log_file):
                return value
        
        # 模糊匹配
        filename_lower = filename.lower()
        if 'auth' in filename_lower:
            return self.LOG_DICTIONARY.get('auth.log', {})
        if 'access' in filename_lower:
            return self.LOG_DICTIONARY.get('access.log', {})
        if 'error' in filename_lower:
            return self.LOG_DICTIONARY.get('error.log', {})
        if 'nginx' in filename_lower:
            if 'access' in filename_lower:
                return self.LOG_DICTIONARY.get('nginx/access.log', {})
            if 'error' in filename_lower:
                return self.LOG_DICTIONARY.get('nginx/error.log', {})
        
        return {}
    
    def _detect_anomalies(self):
        """检测日志文件异常"""
        for log in self.log_files:
            filename = log['name']
            size_mb = log['size_mb']
            
            # 查找阈值
            threshold = self.SIZE_THRESHOLDS.get(filename, self.SIZE_THRESHOLDS['default'])
            
            # 检查是否压缩文件
            if log['is_compressed']:
                threshold *= 3  # 压缩文件可以更大
            
            if size_mb > threshold:
                self.anomalies.append({
                    'file': log['path'],
                    'size_mb': size_mb,
                    'threshold_mb': threshold,
                    'severity': 'high' if size_mb > threshold * 2 else 'medium',
                    'reason': f'文件大小({size_mb}MB)超过阈值({threshold}MB)',
                    'suggestion': self._get_anomaly_suggestion(log)
                })
    
    def _get_anomaly_suggestion(self, log: Dict) -> str:
        """获取异常建议"""
        category = log.get('category', '')
        
        if 'auth' in category.lower():
            return '可能存在暴力破解攻击，建议检查auth.log和btmp'
        if 'access' in category.lower():
            return '访问量异常，可能存在爬虫或攻击'
        if 'error' in category.lower():
            return '应用可能存在问题，建议检查错误详情'
        
        return '建议进一步分析此日志文件'
    
    def _generate_summary(self) -> Dict:
        """生成摘要"""
        total_size = sum(log['size_mb'] for log in self.log_files)
        
        by_category = {}
        for log in self.log_files:
            cat = log['category']
            if cat not in by_category:
                by_category[cat] = {'count': 0, 'size_mb': 0}
            by_category[cat]['count'] += 1
            by_category[cat]['size_mb'] += log['size_mb']
        
        return {
            'total_files': len(self.log_files),
            'total_size_mb': round(total_size, 2),
            'anomaly_count': len(self.anomalies),
            'by_category': by_category
        }
    
    def get_log_dictionary(self) -> Dict:
        """获取日志字典"""
        return self.LOG_DICTIONARY


def analyze_log_files(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：分析日志文件"""
    analyzer = LogFileAnalyzer(target_dir, timeout)
    return analyzer.analyze()
