#!/usr/bin/env python3
"""
重点IP关联分析模块
用于分析访问日志中的IP、统计访问频率、关联服务等
"""

import re
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any, Tuple
import ipaddress
from .utils import safe_execute


class IPAnalyzer:
    """IP分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.ip_data = {}
        self.warnings = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行IP分析"""
        self.ip_data = {
            'log_files': [],
            'all_ips': [],
            'internal_ips': [],
            'external_ips': [],
            'top_ips': [],
            'top_internal_ips': [],
            'top_external_ips': [],
            'ip_log_map': {},
            'ip_counter': Counter()
        }
        
        # 查找访问日志
        result, success, msg = safe_execute(self._find_access_logs, timeout_seconds=self.timeout_seconds)
        if not success:
            self.warnings.append(f"访问日志搜索: {msg}")
        
        # 提取IP
        result, success, msg = safe_execute(self._extract_ips_from_logs, timeout_seconds=self.timeout_seconds)
        if not success:
            self.warnings.append(f"IP提取: {msg}")
        
        # 分类IP
        self._classify_ips()
        self._analyze_ip_statistics()
        
        return {
            'data': self.ip_data,
            'warnings': self.warnings
        }
    
    def _find_access_logs(self, max_logs: int = 20, max_depth: int = 8):
        """查找访问日志文件（带限制）"""
        log_files = []
        
        # 常见日志位置和文件名
        log_patterns = [
            '*access*.log',
            '*access*.txt',
            '*.log'
        ]
        
        log_keywords = ['access', 'log', 'logs', 'apache', 'nginx']
        
        try:
            file_count = 0
            for pattern in log_patterns:
                if file_count >= max_logs * 2:
                    break
                
                for log_file in self.target_dir.rglob(pattern):
                    if file_count >= max_logs * 2:
                        break
                    
                    # 检查深度
                    try:
                        rel_path = log_file.relative_to(self.target_dir)
                        depth = len(rel_path.parts)
                        if depth > max_depth:
                            continue
                    except ValueError:
                        continue
                    
                    log_files.append(log_file)
                    file_count += 1
        except Exception:
            pass
        
        # 过滤
        filtered_logs = []
        for log_file in log_files:
            if len(filtered_logs) >= max_logs:
                break
            
            path_str = str(log_file).lower()
            if any(kw in path_str for kw in log_keywords):
                filtered_logs.append(log_file)
        
        self.ip_data['log_files'] = [str(f) for f in filtered_logs]
    
    def _extract_ips_from_logs(self, max_lines_per_log: int = 10000, max_total_ips: int = 50000):
        """从日志中提取IP（带限制防止内存溢出）"""
        all_ips = []
        ip_log_map = {}
        
        for log_path in self.ip_data.get('log_files', []):
            try:
                log_file = Path(log_path)
                if log_file.exists():
                    # 读取日志，但限制行数
                    line_count = 0
                    ips_from_log = []
                    
                    with log_file.open('r', errors='ignore') as f:
                        for line in f:
                            line_count += 1
                            if line_count > max_lines_per_log:
                                break
                            
                            ips = self._extract_ips_from_text(line)
                            ips_from_log.extend(ips)
                            
                            if len(all_ips) + len(ips_from_log) > max_total_ips:
                                break
                    
                    all_ips.extend(ips_from_log)
                    
                    for ip in ips_from_log:
                        if ip not in ip_log_map:
                            ip_log_map[ip] = []
                        if log_path not in ip_log_map[ip]:
                            ip_log_map[ip].append(log_path)
            
            except Exception:
                continue
        
        self.ip_data['all_ips'] = list(set(all_ips))
        self.ip_data['ip_log_map'] = ip_log_map
        self.ip_data['ip_counter'] = Counter(all_ips)
    
    def _extract_ips_from_text(self, text: str) -> List[str]:
        """从文本中提取IP地址"""
        # IPv4 正则
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ipv4_pattern, text)
        return ips
    
    def _classify_ips(self):
        """分类IP（内网/外网）"""
        internal_ips = []
        external_ips = []
        
        for ip in self.ip_data.get('all_ips', []):
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    internal_ips.append(ip)
                else:
                    external_ips.append(ip)
            except ValueError:
                continue
        
        self.ip_data['internal_ips'] = internal_ips
        self.ip_data['external_ips'] = external_ips
    
    def _analyze_ip_statistics(self):
        """分析IP统计信息"""
        counter = self.ip_data.get('ip_counter', Counter())
        
        # Top 访问IP
        top_ips = counter.most_common(20)
        self.ip_data['top_ips'] = top_ips
        
        # Top 内部IP
        internal_counter = Counter({
            ip: count for ip, count in counter.items()
            if ip in self.ip_data.get('internal_ips', [])
        })
        self.ip_data['top_internal_ips'] = internal_counter.most_common(10)
        
        # Top 外部IP
        external_counter = Counter({
            ip: count for ip, count in counter.items()
            if ip in self.ip_data.get('external_ips', [])
        })
        self.ip_data['top_external_ips'] = external_counter.most_common(10)
    
    def get_ip_summary(self) -> str:
        """获取IP分析摘要"""
        summary = []
        summary.append(f"发现IP数量: {len(self.ip_data.get('all_ips', []))}")
        summary.append(f"内网IP: {len(self.ip_data.get('internal_ips', []))}")
        summary.append(f"外网IP: {len(self.ip_data.get('external_ips', []))}")
        
        top_ips = self.ip_data.get('top_ips', [])
        if top_ips:
            summary.append("\nTop 5 访问IP:")
            for i, (ip, count) in enumerate(top_ips[:5], 1):
                ip_type = "内网" if ip in self.ip_data.get('internal_ips', []) else "外网"
                summary.append(f"  {i}. {ip} ({ip_type}) - {count}次")
        
        return "\n".join(summary)
