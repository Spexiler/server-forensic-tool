#!/usr/bin/env python3
"""
时间线分析模块 v2.0
从日志中提取带时间戳的事件，生成时间线视图
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime
from .utils import safe_execute


class TimelineAnalyzer:
    """时间线分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30, max_events: int = 1000):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.max_events = max_events
        self.warnings = []
        self.events = []
        self.filters = {}
    
    def analyze(self, ssh_security_data: Dict = None, 
                access_log_data: Dict = None) -> Dict[str, Any]:
        """执行时间线分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"时间线分析: {msg}")
        
        # 合并外部数据
        if ssh_security_data:
            self._merge_ssh_events(ssh_security_data)
        if access_log_data:
            self._merge_access_events(access_log_data)
        
        # 排序事件
        self._sort_events()
        
        return {
            'data': {
                'events': self.events[:self.max_events],
                'total_events': len(self.events),
                'summary': self._generate_summary()
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._scan_log_files()
    
    def _scan_log_files(self):
        """扫描日志文件提取事件"""
        log_files = []
        
        # 扫描所有日志文件
        for pattern in ['*.log', 'syslog', 'auth.log', 'messages']:
            log_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描标准目录
        for log_dir in [
            Path('/var/log/'),
            Path('/var/log/nginx/'),
            Path('/var/log/apache2/'),
        ]:
            if log_dir.exists():
                log_files.extend(log_dir.glob('*.log'))
        
        for log_file in log_files[:50]:  # 限制数量
            self._extract_events_from_log(log_file)
    
    def _extract_events_from_log(self, log_file: Path):
        """从日志文件提取事件"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if len(self.events) >= self.max_events * 2:
                        break
                    
                    event = self._parse_log_line(line, str(log_file))
                    if event:
                        self.events.append(event)
        
        except Exception:
            pass
    
    def _parse_log_line(self, line: str, source: str) -> Optional[Dict]:
        """解析日志行，提取事件"""
        if not line or len(line) < 10:
            return None
        
        timestamp = self._extract_timestamp(line)
        if not timestamp:
            return None
        
        # 分类事件
        category = self._categorize_event(line)
        
        # 提取关键信息
        message = self._extract_key_message(line)
        
        # 提取IP（如果有）
        ip = self._extract_ip(line)
        
        return {
            'timestamp': timestamp,
            'raw': line[:200],
            'category': category,
            'message': message,
            'ip': ip,
            'source': Path(source).name
        }
    
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """提取时间戳"""
        # 格式1: May 11 15:51:56
        match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        if match:
            return match.group(1)
        
        # 格式2: 2026-05-11T15:51:56
        match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if match:
            return match.group(1)
        
        # 格式3: [11/May/2026:15:51:56
        match = re.search(r'\[(\d+/\w+/\d+:\d+:\d+:\d+)', line)
        if match:
            return match.group(1)
        
        return None
    
    def _categorize_event(self, line: str) -> str:
        """分类事件"""
        line_lower = line.lower()
        
        # 认证类
        if any(x in line_lower for x in ['failed', 'failed password', 'authentication failure']):
            return '认证-失败'
        if any(x in line_lower for x in ['accepted', 'accepted password', 'successful']):
            return '认证-成功'
        if 'connection closed' in line_lower:
            return '连接-关闭'
        
        # 网络类
        if any(x in line_lower for x in ['connect', 'connected', 'disconnect']):
            return '连接'
        
        # 服务类
        if any(x in line_lower for x in ['started', 'stopped', 'restart', 'reload']):
            return '服务-状态'
        if any(x in line_lower for x in ['error', 'failed', 'critical']):
            return '错误'
        if 'warning' in line_lower:
            return '警告'
        
        # Web类
        if any(x in line_lower for x in ['get ', 'post ', 'http', 'status code']):
            return 'Web请求'
        
        # 安全类
        if any(x in line_lower for x in ['block', 'denied', 'reject', 'ban']):
            return '安全-拦截'
        if any(x in line_lower for x in ['firewall', 'ufw', 'iptables']):
            return '防火墙'
        
        # SSH类
        if 'ssh' in line_lower:
            return 'SSH'
        
        return '其他'
    
    def _extract_key_message(self, line: str) -> str:
        """提取关键消息"""
        # 移除时间戳
        msg = re.sub(r'^\w+\s+\d+\s+\d+:\d+:\d+\s+', '', line)
        
        # 移除日志源
        msg = re.sub(r'^\S+:\s*', '', msg)
        
        # 截断过长消息
        if len(msg) > 100:
            msg = msg[:100] + '...'
        
        return msg.strip()
    
    def _extract_ip(self, line: str) -> Optional[str]:
        """提取IP地址"""
        # 常见IP格式
        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
        if match:
            ip = match.group(1)
            # 排除广播和组播
            if not ip.startswith('255') and not ip.startswith('0'):
                return ip
        return None
    
    def _merge_ssh_events(self, ssh_data: Dict):
        """合并SSH事件"""
        timeline = ssh_data.get('data', {}).get('attack_timeline', [])
        
        for event in timeline:
            timestamp = event.get('timestamp', '')
            event_type = event.get('type', '')
            
            if timestamp:
                self.events.append({
                    'timestamp': timestamp,
                    'category': 'SSH-' + event_type.replace('_', '-'),
                    'message': f"SSH {event_type.replace('_', ' ')}: {event.get('user', 'unknown')}",
                    'ip': event.get('ip'),
                    'source': 'auth.log',
                    'raw': f"SSH {event_type} for {event.get('user')} from {event.get('ip')}"
                })
    
    def _merge_access_events(self, access_data: Dict):
        """合并访问日志事件"""
        # 从错误请求中提取事件
        errors = access_data.get('data', {}).get('error_requests', [])
        
        for error in errors[:100]:  # 限制数量
            time_str = error.get('time', '')
            if time_str:
                self.events.append({
                    'timestamp': time_str,
                    'category': 'Web-错误',
                    'message': f"HTTP {error.get('status')} - {error.get('path', '/')}",
                    'ip': error.get('ip'),
                    'source': error.get('source', 'access.log'),
                    'raw': f"{error.get('ip')} - [{time_str}] \"{error.get('path')}\" {error.get('status')}"
                })
    
    def _sort_events(self):
        """排序事件"""
        def parse_date(event):
            timestamp = event.get('timestamp', '')
            
            # 尝试解析时间
            try:
                # 格式: May 11 15:51:56 -> 2026-05-11 15:51:56
                if re.match(r'^\w+\s+\d+\s+\d+:\d+:\d+$', timestamp):
                    dt = datetime.strptime(f"2026-{timestamp}", "%Y-%b %d %H:%M:%S")
                    return dt
                
                # 格式: 2026-05-11T15:51:56
                if 'T' in timestamp or '-' in timestamp[:10]:
                    dt = datetime.fromisoformat(timestamp.replace('/', '-'))
                    return dt
                
            except:
                pass
            
            return datetime.min
        
        self.events.sort(key=parse_date, reverse=True)
    
    def _generate_summary(self) -> Dict:
        """生成摘要"""
        summary = {
            'total_events': len(self.events),
            'by_category': defaultdict(int),
            'top_ips': defaultdict(int),
            'time_range': None
        }
        
        # 按类别统计
        for event in self.events:
            category = event.get('category', '其他')
            summary['by_category'][category] += 1
            
            ip = event.get('ip')
            if ip:
                summary['top_ips'][ip] += 1
        
        # 时间范围
        if self.events:
            first = self.events[-1].get('timestamp', '')
            last = self.events[0].get('timestamp', '')
            summary['time_range'] = f"{first} ~ {last}"
        
        summary['by_category'] = dict(summary['by_category'])
        summary['top_ips'] = dict(sorted(summary['top_ips'].items(), key=lambda x: -x[1])[:10])
        
        return summary
    
    def filter_by_category(self, category: str):
        """按类别过滤"""
        self.filters['category'] = category
    
    def filter_by_ip(self, ip: str):
        """按IP过滤"""
        self.filters['ip'] = ip
    
    def filter_by_timerange(self, start: str, end: str):
        """按时间范围过滤"""
        self.filters['timerange'] = (start, end)
    
    def get_filtered_events(self) -> List[Dict]:
        """获取过滤后的事件"""
        filtered = self.events
        
        if 'category' in self.filters:
            filtered = [e for e in filtered if e.get('category') == self.filters['category']]
        
        if 'ip' in self.filters:
            filtered = [e for e in filtered if e.get('ip') == self.filters['ip']]
        
        return filtered


def analyze_timeline(target_dir: str, timeout: int = 30,
                    ssh_data: Dict = None, 
                    access_data: Dict = None) -> Dict[str, Any]:
    """便捷函数：分析时间线"""
    analyzer = TimelineAnalyzer(target_dir, timeout)
    return analyzer.analyze(ssh_data, access_data)
