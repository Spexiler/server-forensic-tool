#!/usr/bin/env python3
"""
任务量评估和超时管理模块
"""

import os
from pathlib import Path
from typing import Dict, Any, Tuple


class TaskEstimator:
    """任务量评估器"""
    
    # 超时配置（秒）
    DEFAULT_TIMEOUT = 30
    MIN_TIMEOUT = 10
    MAX_TIMEOUT = 300
    
    # 任务复杂度系数
    COMPLEXITY_WEIGHTS = {
        'service_config': 1.0,    # 服务配置分析
        'network': 0.5,           # 网络分析（通常较快）
        'ip_analysis': 1.5,       # IP分析（涉及日志读取）
        'server_role': 0.5,       # 角色识别（计算量小）
        'reporter': 1.0,          # 报告生成
    }
    
    # 目录大小阈值（MB）
    SIZE_THRESHOLDS = {
        'small': 10,      # 小型目录 < 10MB
        'medium': 100,    # 中型目录 < 100MB
        'large': 500,     # 大型目录 < 500MB
        'huge': float('inf')  # 超大型目录
    }
    
    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir)
        self.stats = {}
    
    def estimate(self) -> Dict[str, Any]:
        """评估任务量并返回建议的超时配置"""
        self._scan_directory()
        base_timeout = self._calculate_base_timeout()
        
        timeout_config = {
            'service_config': int(base_timeout * self.COMPLEXITY_WEIGHTS['service_config']),
            'network': int(base_timeout * self.COMPLEXITY_WEIGHTS['network']),
            'ip_analysis': int(base_timeout * self.COMPLEXITY_WEIGHTS['ip_analysis']),
            'server_role': int(base_timeout * self.COMPLEXITY_WEIGHTS['server_role']),
            'reporter': int(base_timeout * self.COMPLEXITY_WEIGHTS['reporter']),
            'overall': base_timeout,
            'stats': self.stats
        }
        
        return timeout_config
    
    def _scan_directory(self):
        """扫描目录获取统计信息"""
        stats = {
            'total_files': 0,
            'total_dirs': 0,
            'total_size': 0,  # bytes
            'file_types': {},  # 扩展名统计
            'log_files': 0,
            'config_files': 0,
            'estimated_complexity': 'low'
        }
        
        try:
            for root, dirs, files in os.walk(self.target_dir):
                stats['total_dirs'] += len(dirs)
                
                for file in files:
                    stats['total_files'] += 1
                    file_path = Path(root) / file
                    
                    try:
                        size = file_path.stat().st_size
                        stats['total_size'] += size
                    except (OSError, PermissionError):
                        continue
                    
                    # 统计文件类型
                    ext = file_path.suffix.lower()
                    if ext:
                        stats['file_types'][ext] = stats['file_types'].get(ext, 0) + 1
                    else:
                        stats['file_types']['[无扩展名]'] = \
                            stats['file_types'].get('[无扩展名]', 0) + 1
                    
                    # 统计日志文件
                    if any(kw in file.lower() for kw in ['log', 'access', 'error']):
                        stats['log_files'] += 1
                    
                    # 统计配置文件
                    if any(kw in file.lower() for kw in ['conf', 'config', '.ini', '.cfg']):
                        stats['config_files'] += 1
        
        except (OSError, PermissionError) as e:
            stats['error'] = str(e)
        
        # 计算复杂度
        stats['size_mb'] = stats['total_size'] / (1024 * 1024)
        
        if stats['size_mb'] < self.SIZE_THRESHOLDS['small']:
            stats['estimated_complexity'] = 'low'
        elif stats['size_mb'] < self.SIZE_THRESHOLDS['medium']:
            stats['estimated_complexity'] = 'medium'
        elif stats['size_mb'] < self.SIZE_THRESHOLDS['large']:
            stats['estimated_complexity'] = 'high'
        else:
            stats['estimated_complexity'] = 'very_high'
        
        self.stats = stats
    
    def _calculate_base_timeout(self) -> int:
        """根据目录信息计算基础超时时间"""
        size_mb = self.stats.get('size_mb', 0)
        total_files = self.stats.get('total_files', 0)
        log_files = self.stats.get('log_files', 0)
        
        # 基础超时
        base = self.DEFAULT_TIMEOUT
        
        # 根据大小调整
        if size_mb > self.SIZE_THRESHOLDS['large']:
            base = 120  # 大目录增加超时
        elif size_mb > self.SIZE_THRESHOLDS['medium']:
            base = 60
        elif size_mb < 1:  # 小目录可以减少超时
            base = 20
        
        # 根据文件数量调整
        if total_files > 10000:
            base = max(base, 90)
        elif total_files > 5000:
            base = max(base, 60)
        
        # 日志文件越多，可能需要更长的分析时间
        if log_files > 10:
            base = max(base, 45)  # IP分析需要更多时间
        
        # 确保在有效范围内
        return max(self.MIN_TIMEOUT, min(base, self.MAX_TIMEOUT))
    
    def get_summary(self) -> str:
        """获取评估摘要"""
        stats = self.stats
        timeout_config = self.estimate()
        
        lines = [
            "目录评估结果:",
            f"  - 文件数量: {stats.get('total_files', 0):,}",
            f"  - 目录数量: {stats.get('total_dirs', 0):,}",
            f"  - 总大小: {stats.get('size_mb', 0):.2f} MB",
            f"  - 日志文件: {stats.get('log_files', 0):,}",
            f"  - 配置文件: {stats.get('config_files', 0):,}",
            f"  - 预估复杂度: {stats.get('estimated_complexity', 'unknown')}",
            f"",
            f"建议超时配置:",
            f"  - 服务配置: {timeout_config['service_config']}秒",
            f"  - 网络分析: {timeout_config['network']}秒",
            f"  - IP分析: {timeout_config['ip_analysis']}秒",
            f"  - 角色识别: {timeout_config['server_role']}秒",
            f"  - 报告生成: {timeout_config['reporter']}秒",
        ]
        
        return "\n".join(lines)


def estimate_task_size(target_dir: str) -> Dict[str, Any]:
    """快速评估任务大小"""
    estimator = TaskEstimator(target_dir)
    return estimator.estimate()


def get_adaptive_timeout(target_dir: str, task_type: str = 'overall') -> int:
    """获取自适应超时时间"""
    config = estimate_task_size(target_dir)
    return config.get(task_type, config.get('overall', 30))
