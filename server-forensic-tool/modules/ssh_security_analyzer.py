#!/usr/bin/env python3
"""
SSH安全态势评估模块 v2.0
分析SSH登录日志，评估安全性
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime
from .utils import safe_execute


class SSHSecurityAnalyzer:
    """SSH安全分析器"""
    
    # 常见SSH用户名（用于暴力破解识别）
    COMMON_USERNAMES = {
        'root', 'admin', 'user', 'test', 'ubuntu', 'centos',
        'debian', 'oracle', 'mysql', 'postgres', 'nginx', 'apache',
        'backup', 'guest', 'support', 'administrator', 'master',
        'info', 'www', 'web', 'ftp', 'mail', 'ssh'
    }
    
    # 高危用户名
    HIGH_RISK_USERNAMES = {'root', 'admin', 'administrator'}
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30, max_lines: int = 100000):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.max_lines = max_lines
        self.warnings = []
        
        self.ssh_config = {}
        self.failed_logins = []
        self.successful_logins = []
        self.attacked_usernames = Counter()
        self.attacker_ips = Counter()
        self.timeline = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行SSH安全分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"SSH安全分析: {msg}")
        
        return {
            'data': {
                'failed_logins': len(self.failed_logins),
                'successful_logins': len(self.successful_logins),
                'top_attackers': self.attacker_ips.most_common(10),
                'top_target_usernames': self.attacked_usernames.most_common(10),
                'ssh_config': self.ssh_config,
                'security_issues': self._assess_security(),
                'recommendations': self._generate_recommendations(),
                'attack_timeline': self.timeline[:50],  # 最近50条
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        # 分析SSH配置文件
        self._analyze_ssh_config()
        
        # 查找并分析SSH日志
        self._analyze_ssh_logs()
    
    def _analyze_ssh_config(self):
        """分析SSH配置文件"""
        config_paths = [
            Path('/etc/ssh/sshd_config'),
            Path('/etc/sshd_config'),
        ]
        
        # 扫描目标目录
        for pattern in ['sshd_config', '*ssh*config*']:
            for config_file in self.target_dir.rglob(pattern):
                try:
                    self._parse_ssh_config(config_file)
                    return
                except Exception:
                    continue
        
        # 扫描标准路径
        for config_path in config_paths:
            if config_path.exists():
                try:
                    self._parse_ssh_config(config_path)
                    return
                except Exception:
                    continue
    
    def _parse_ssh_config(self, config_file: Path):
        """解析SSH配置文件"""
        content = config_file.read_text(errors='ignore')
        
        # 关键配置项
        self.ssh_config = {
            'config_file': str(config_file),
            'password_auth': False,
            'root_login': False,
            'port': 22,
            'permit_empty_passwords': False,
            'x11_forwarding': True,
        }
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            
            # 密码认证
            if 'PasswordAuthentication yes' in line:
                self.ssh_config['password_auth'] = True
            elif 'PasswordAuthentication no' in line:
                self.ssh_config['password_auth'] = False
            
            # Root登录
            if 'PermitRootLogin yes' in line:
                self.ssh_config['root_login'] = True
            elif 'PermitRootLogin no' in line:
                self.ssh_config['root_login'] = False
            
            # SSH端口
            port_match = re.match(r'^Port\s+(\d+)', line)
            if port_match:
                self.ssh_config['port'] = int(port_match.group(1))
            
            # 空密码
            if 'PermitEmptyPasswords yes' in line:
                self.ssh_config['permit_empty_passwords'] = True
            
            # X11转发
            if 'X11Forwarding no' in line:
                self.ssh_config['x11_forwarding'] = False
    
    def _analyze_ssh_logs(self):
        """分析SSH日志"""
        log_files = self._find_ssh_logs()
        
        if not log_files:
            self.warnings.append("未发现SSH日志文件")
            return
        
        for log_file in log_files:
            self._parse_ssh_log(log_file)
    
    def _find_ssh_logs(self) -> List[Path]:
        """查找SSH日志文件"""
        log_files = []
        
        # auth.log (Debian/Ubuntu)
        auth_logs = [
            Path('/var/log/auth.log'),
            Path('/var/log/auth.log.gz'),
            Path('/var/log/secure'),  # RHEL/CentOS
            Path('/var/log/secure-*'),
        ]
        
        for log_path in auth_logs:
            if log_path.exists():
                log_files.append(log_path)
        
        # 扫描目标目录
        for pattern in ['auth.log*', 'secure*', '*ssh*log*', '*btmp*']:
            log_files.extend(self.target_dir.rglob(pattern))
        
        return list(set(log_files))
    
    def _parse_ssh_log(self, log_file: Path):
        """解析SSH日志文件"""
        try:
            # 处理.gz文件
            if str(log_file).endswith('.gz'):
                import gzip
                opener = lambda f: gzip.open(f, 'rt', errors='ignore')
            else:
                opener = lambda f: open(f, 'r', errors='ignore')
            
            with opener(log_file) as f:
                for i, line in enumerate(f):
                    if i >= self.max_lines:
                        break
                    self._parse_ssh_log_line(line.strip(), str(log_file))
        
        except Exception as e:
            self.warnings.append(f"解析SSH日志失败 {log_file}: {e}")
    
    def _parse_ssh_log_line(self, line: str, source: str):
        """解析单行SSH日志"""
        if not line:
            return
        
        # 失败登录
        failed_patterns = [
            r'Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)',
            r'FAILED (?P<user>\S+) from (?P<ip>[\d.]+)',
            r'Failed (?:publickey|password) for (?P<user>\S+) from (?P<ip>[\d.]+)',
        ]
        
        for pattern in failed_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                user = match.group('user')
                ip = match.group('ip')
                
                # 提取时间
                timestamp = self._extract_timestamp(line)
                
                self.failed_logins.append({
                    'timestamp': timestamp,
                    'user': user,
                    'ip': ip,
                    'source': source,
                    'line': line[:100]
                })
                
                self.attacker_ips[ip] += 1
                self.attacked_usernames[user] += 1
                
                # 记录到时间线
                if timestamp:
                    self.timeline.append({
                        'timestamp': timestamp,
                        'type': 'failed_login',
                        'user': user,
                        'ip': ip
                    })
                return
        
        # 成功登录
        success_patterns = [
            r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)',
            r'Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+)',
            r'ROOT LOGIN REFUSED from (?P<ip>[\d.]+)',
        ]
        
        for pattern in success_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                user = match.group('user')
                ip = match.group('ip')
                
                timestamp = self._extract_timestamp(line)
                
                self.successful_logins.append({
                    'timestamp': timestamp,
                    'user': user,
                    'ip': ip,
                    'source': source,
                    'line': line[:100]
                })
                
                # 记录到时间线
                if timestamp:
                    self.timeline.append({
                        'timestamp': timestamp,
                        'type': 'success_login',
                        'user': user,
                        'ip': ip
                    })
                return
        
        # 连接关闭
        if 'Connection closed by' in line:
            match = re.search(r'Connection closed by (?P<user>[\w]+) (?P<ip>[\d.]+)', line)
            if match:
                timestamp = self._extract_timestamp(line)
                if timestamp:
                    self.timeline.append({
                        'timestamp': timestamp,
                        'type': 'connection_closed',
                        'user': match.group('user'),
                        'ip': match.group('ip')
                    })
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """提取时间戳"""
        # 格式: May 11 15:51:56
        match = re.search(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        if match:
            return match.group(1)
        
        # 格式: 2026-05-11T15:51:56
        match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if match:
            return match.group(1)
        
        return None
    
    def _assess_security(self) -> List[Dict]:
        """评估安全问题"""
        issues = []
        
        # 检查SSH配置问题
        if self.ssh_config.get('password_auth'):
            issues.append({
                'severity': 'high',
                'issue': '允许密码认证',
                'description': '建议改用密钥认证以防止暴力破解'
            })
        
        if self.ssh_config.get('root_login'):
            issues.append({
                'severity': 'high',
                'issue': '允许root登录',
                'description': '建议禁用root登录，使用普通用户sudo'
            })
        
        if self.ssh_config.get('port') == 22:
            issues.append({
                'severity': 'medium',
                'issue': '使用默认端口22',
                'description': '建议修改为非标准端口减少扫描'
            })
        
        # 检查暴力破解
        if len(self.failed_logins) > 100:
            issues.append({
                'severity': 'critical',
                'issue': '检测到大量SSH暴力破解',
                'description': f'共{len(self.failed_logins)}次失败登录，建议安装fail2ban'
            })
        elif len(self.failed_logins) > 10:
            issues.append({
                'severity': 'medium',
                'issue': '检测到SSH失败登录',
                'description': f'共{len(self.failed_logins)}次失败登录'
            })
        
        # 检查是否针对高危用户
        for user, count in self.attacked_usernames.most_common(5):
            if user in self.HIGH_RISK_USERNAMES and count > 10:
                issues.append({
                    'severity': 'high',
                    'issue': f'高危用户{user}被{count}次攻击',
                    'description': '建议禁用该用户或改用密钥认证'
                })
        
        return issues
    
    def _generate_recommendations(self) -> List[str]:
        """生成安全加固建议"""
        recommendations = []
        
        # 基于发现的问题生成建议
        if self.ssh_config.get('password_auth'):
            recommendations.append('禁用密码认证，改用SSH密钥认证')
        
        if self.ssh_config.get('root_login'):
            recommendations.append('禁用root SSH登录')
        
        if len(self.failed_logins) > 0:
            recommendations.append('安装并配置fail2ban自动封禁攻击IP')
        
        if self.ssh_config.get('port') == 22:
            recommendations.append('将SSH端口修改为非标准端口（如22022）')
        
        recommendations.append('限制允许SSH登录的用户列表（AllowUsers）')
        recommendations.append('启用SSH日志审计和监控')
        
        # 如果没有发现问题，给出基线建议
        if not recommendations:
            recommendations.append('SSH配置较为安全，建议保持当前配置')
            recommendations.append('定期检查SSH日志，关注异常登录')
        
        return recommendations
    
    def get_security_report(self) -> str:
        """获取安全报告摘要"""
        lines = []
        lines.append("【SSH安全评估报告】")
        lines.append("=" * 50)
        
        # 统计
        lines.append(f"\n失败登录尝试: {len(self.failed_logins)}次")
        lines.append(f"成功登录: {len(self.successful_logins)}次")
        lines.append(f"攻击来源IP: {len(self.attacker_ips)}个")
        
        # Top攻击者
        if self.attacker_ips:
            lines.append("\nTop 5 攻击源:")
            for ip, count in self.attacker_ips.most_common(5):
                lines.append(f"  {ip}: {count}次")
        
        # 安全问题
        issues = self._assess_security()
        if issues:
            lines.append("\n发现问题:")
            for issue in issues:
                severity_icon = "🔴" if issue['severity'] == 'critical' else "🟡"
                lines.append(f"  {severity_icon} {issue['issue']}")
        
        # 建议
        recommendations = self._generate_recommendations()
        if recommendations:
            lines.append("\n安全建议:")
            for rec in recommendations:
                lines.append(f"  ✓ {rec}")
        
        return "\n".join(lines)


def analyze_ssh_security(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：分析SSH安全"""
    analyzer = SSHSecurityAnalyzer(target_dir, timeout)
    return analyzer.analyze()
