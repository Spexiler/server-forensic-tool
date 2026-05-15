#!/usr/bin/env python3
"""
Web访问日志智能分析模块 v2.0
解析access.log，提取请求模式、UA指纹、状态码分布
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from datetime import datetime
from .utils import safe_execute


class AccessLogAnalyzer:
    """访问日志分析器"""
    
    # Nginx combined日志格式
    NGINX_PATTERN = re.compile(
        r'(?P<ip>[\d.]+)\s+-\s+-\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<ua>[^"]*)"'
    )
    
    # Apache combined日志格式
    APACHE_PATTERN = re.compile(
        r'(?P<ip>[\d.]+)\s+'
        r'(?P<ident>[^\s]+)\s+'
        r'(?P<user>[^\s]+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )
    
    # 常见爬虫和工具的UA特征
    UA_SIGNATURES = {
        'curl': ['curl', 'libcurl'],
        'wget': ['wget'],
        'python-requests': ['python-requests', 'python\\.requests'],
        'aiohttp': ['aiohttp'],
        'scrapy': ['scrapy'],
        'chrome': ['chrome', 'chromium'],
        'firefox': ['firefox'],
        'safari': ['safari'],
        'edge': ['edge'],
        'mobile_chrome': ['mobile chrome', 'android.*chrome'],
        'mobile_safari': ['mobile safari', 'iphone', 'ipad'],
        'baidu_spider': ['baidu'],
        'google_bot': ['googlebot', 'google-inspectiontool'],
        'bing_bot': ['bingbot', 'msnbot'],
        'yandex_bot': ['yandexbot'],
        'admin_tools': ['nmap', 'masscan', 'sqlmap', 'nikto', 'metasploit'],
        'unknown_bot': ['bot', 'crawler', 'spider', 'scraper'],
    }
    
    # 常见客户端应用特征
    APP_SIGNATURES = {
        'SuperAccelerator': ['superaccelerator', 'superv2ray', 'v2rayng', 'clash'],
        'Shadowsocks': ['shadowsocks', 'ss-local', 'shadowsock'],
        'V2Ray': ['v2ray', 'v2fly', 'xray'],
        'Trojan': ['trojan', 'trojan-go'],
        'WireGuard': ['wireguard'],
        'OpenVPN': ['openvpn'],
        'SSH': ['ssh'],
        'SFTP': ['sftp'],
    }
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30, max_lines: int = 100000):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.max_lines = max_lines
        self.warnings = []
        
        self.stats = {
            'total_requests': 0,
            'unique_ips': set(),
            'top_paths': Counter(),
            'top_ips': Counter(),
            'top_user_agents': Counter(),
            'status_distribution': Counter(),
            'method_distribution': Counter(),
            'api_patterns': [],
            'suspicious_activities': [],
            'time_distribution': defaultdict(int),
            'error_requests': [],
        }
    
    def analyze(self) -> Dict[str, Any]:
        """执行访问日志分析"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"访问日志分析: {msg}")
        
        # 转换set为list用于JSON序列化
        stats = self.stats.copy()
        stats['unique_ips'] = list(stats['unique_ips'])
        
        # 转换Counter为dict
        stats['top_paths'] = dict(stats['top_paths'].most_common(20))
        stats['top_ips'] = dict(stats['top_ips'].most_common(20))
        stats['top_user_agents'] = dict(stats['top_user_agents'].most_common(20))
        stats['status_distribution'] = dict(stats['status_distribution'])
        stats['method_distribution'] = dict(stats['method_distribution'])
        stats['time_distribution'] = dict(stats['time_distribution'])
        
        return {
            'data': {
                **stats,
                'total_requests': self.stats['total_requests'],
                'unique_ip_count': len(self.stats['unique_ips']),
                'anomalies': self._detect_anomalies(),
                'api_analysis': self._analyze_api_patterns(),
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        log_files = self._find_access_logs()
        
        if not log_files:
            self.warnings.append("未发现访问日志文件")
            return
        
        for log_file in log_files:
            self._parse_log_file(log_file)
        
        # 分析API模式
        self._detect_api_patterns()
    
    def _find_access_logs(self) -> List[Path]:
        """查找访问日志文件"""
        log_files = []
        
        # 常见日志位置
        log_patterns = [
            '*access*.log',
            '*access*.txt',
            '*access.log*',
            'nginx/*.log',
            'apache2/*.log',
            'httpd/*.log',
        ]
        
        # 扫描目标目录
        for pattern in log_patterns:
            log_files.extend(self.target_dir.rglob(pattern))
        
        # 扫描/var/log目录（Linux服务器）
        var_log_paths = [
            Path('/var/log/nginx'),
            Path('/var/log/apache2'),
            Path('/var/log/httpd'),
        ]
        
        for log_dir in var_log_paths:
            if log_dir.exists():
                for pattern in ['*access*.log', '*.log']:
                    log_files.extend(log_dir.glob(pattern))
        
        # 去重
        return list(set(log_files))
    
    def _parse_log_file(self, log_file: Path):
        """解析单个日志文件"""
        try:
            with open(log_file, 'r', errors='ignore', encoding='utf-8', buffering=8192) as f:
                for i, line in enumerate(f):
                    if i >= self.max_lines:
                        break
                    
                    self._parse_log_line(line.strip(), str(log_file))
        
        except Exception as e:
            self.warnings.append(f"解析日志文件失败 {log_file}: {e}")
    
    def _parse_log_line(self, line: str, source: str):
        """解析单行日志"""
        if not line or line.startswith('#'):
            return
        
        # 尝试Nginx格式
        match = self.NGINX_PATTERN.match(line)
        if match:
            self._process_parsed_log(match.groupdict(), source)
            return
        
        # 尝试Apache格式
        match = self.APACHE_PATTERN.match(line)
        if match:
            self._process_parsed_log(match.groupdict(), source)
            return
        
        # 尝试其他格式
        self._parse_generic_log(line, source)
    
    def _process_parsed_log(self, data: Dict, source: str):
        """处理解析后的日志数据"""
        self.stats['total_requests'] += 1
        
        ip = data.get('ip', '')
        path = data.get('path', '/')
        status = data.get('status', '0')
        ua = data.get('ua', '')
        method = data.get('method', 'GET')
        size = data.get('size', '0')
        time_str = data.get('time', '')
        
        # IP统计
        if ip:
            self.stats['unique_ips'].add(ip)
            self.stats['top_ips'][ip] += 1
        
        # 路径统计
        if path:
            self.stats['top_paths'][path] += 1
        
        # UA统计
        if ua:
            self.stats['top_user_agents'][ua] += 1
        
        # 状态码统计
        try:
            status_code = int(status)
            self.stats['status_distribution'][status] += 1
            
            # 记录错误请求
            if status_code >= 400:
                self.stats['error_requests'].append({
                    'time': time_str,
                    'ip': ip,
                    'path': path,
                    'status': status,
                    'ua': ua[:50],
                    'source': source
                })
        except ValueError:
            pass
        
        # 方法统计
        self.stats['method_distribution'][method] += 1
        
        # 时间分布（按小时）
        if time_str:
            hour = self._extract_hour(time_str)
            if hour is not None:
                self.stats['time_distribution'][hour] += 1
        
        # 检测可疑活动
        self._detect_suspicious_request(ip, path, ua, method)
    
    def _parse_generic_log(self, line: str, source: str):
        """解析通用格式日志"""
        # 尝试提取IP
        ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            self.stats['unique_ips'].add(ip_match.group(1))
            self.stats['top_ips'][ip_match.group(1)] += 1
        
        # 尝试提取状态码
        status_match = re.search(r'\s(\d{3})\s', line)
        if status_match:
            self.stats['status_distribution'][status_match.group(1)] += 1
        
        self.stats['total_requests'] += 1
    
    def _extract_hour(self, time_str: str) -> Optional[int]:
        """从时间字符串提取小时"""
        try:
            # 格式: 11/May/2026:15:51:56
            match = re.search(r':(\d{2}):\d{2}:\d{2}', time_str)
            if match:
                return int(match.group(1))
        except:
            pass
        return None
    
    def _detect_suspicious_request(self, ip: str, path: str, ua: str, method: str):
        """检测可疑请求"""
        suspicious = []
        
        # 敏感路径探测
        sensitive_paths = [
            '/admin', '/wp-admin', '/wp-login', '/phpmyadmin',
            '/.env', '/.git', '/config', '/backup',
            '/wp-config', '/xmlrpc.php', '/wp-json',
            '/admin.php', '/login', '/administrator',
        ]
        
        path_lower = path.lower()
        for sensitive in sensitive_paths:
            if sensitive in path_lower:
                suspicious.append(f"探测敏感路径: {path}")
                break
        
        # 扫描器UA
        ua_lower = ua.lower()
        for tool_name, patterns in self.UA_SIGNATURES.items():
            if tool_name in ['admin_tools', 'unknown_bot']:
                for pattern in patterns:
                    if re.search(pattern, ua_lower, re.IGNORECASE):
                        suspicious.append(f"扫描器UA: {tool_name}")
                        break
        
        # 异常方法
        if method not in ['GET', 'POST', 'HEAD']:
            suspicious.append(f"异常HTTP方法: {method}")
        
        # 无UA请求
        if not ua or ua == '-':
            suspicious.append("无User-Agent的请求")
        
        if suspicious:
            self.stats['suspicious_activities'].append({
                'ip': ip,
                'path': path,
                'reasons': suspicious
            })
    
    def _detect_api_patterns(self):
        """检测API模式"""
        api_patterns = defaultdict(int)
        
        for path, count in self.stats['top_paths'].items():
            # 常见的API模式
            if re.match(r'^/api/v\d+/', path):
                api_patterns['RESTful API (v1+)'] += count
            elif re.match(r'^/api/', path):
                api_patterns['RESTful API'] += count
            elif re.match(r'^/v\d+/', path):
                api_patterns['Version API'] += count
            elif re.search(r'\.(json|xml)$', path):
                api_patterns['数据接口'] += count
            elif '/?' in path:
                # 可能是动态页面
                if any(x in path for x in ['id=', 'page=', 'user=']):
                    api_patterns['动态页面'] += count
            else:
                api_patterns['静态资源'] += count
        
        self.stats['api_patterns'] = dict(api_patterns)
    
    def _analyze_api_patterns(self) -> Dict:
        """分析API模式详情"""
        patterns = {}
        
        # 提取RESTful API端点
        rest_endpoints = []
        for path in self.stats['top_paths'].keys():
            if re.match(r'^/api/v\d+/', path):
                # 提取端点模板
                endpoint = re.sub(r'/\d+', '/{id}', path)
                if endpoint not in rest_endpoints:
                    rest_endpoints.append(endpoint)
        
        if rest_endpoints:
            patterns['RESTful端点'] = rest_endpoints[:10]
        
        # 识别应用类型
        app_type = self._identify_application_type()
        if app_type:
            patterns['应用类型'] = app_type
        
        return patterns
    
    def _identify_application_type(self) -> Optional[str]:
        """根据日志特征识别应用类型"""
        # 检查UA
        all_ua = ' '.join(self.stats['top_user_agents'].keys()).lower()
        
        for app_name, patterns in self.APP_SIGNATURES.items():
            for pattern in patterns:
                if pattern.lower() in all_ua:
                    return app_name
        
        # 检查路径
        all_paths = ' '.join(self.stats['top_paths'].keys()).lower()
        
        if 'v2board' in all_paths or 'v2ray' in all_paths:
            return 'V2Board'
        if 'ss' in all_paths or 'shadowsocks' in all_paths:
            return 'ShadowSocks'
        if 'xray' in all_paths:
            return 'Xray'
        
        return None
    
    def _detect_anomalies(self) -> List[Dict]:
        """检测异常"""
        anomalies = []
        
        # 高频IP
        for ip, count in self.stats['top_ips'].items():
            if count > 1000:  # 超过1000次请求
                anomalies.append({
                    'type': '高频访问',
                    'ip': ip,
                    'count': count,
                    'severity': 'high' if count > 5000 else 'medium'
                })
        
        # 大量404
        if self.stats['status_distribution'].get('404', 0) > 100:
            anomalies.append({
                'type': '大量404错误',
                'count': self.stats['status_distribution']['404'],
                'severity': 'medium'
            })
        
        # 可疑爬虫
        if len(self.stats['suspicious_activities']) > 10:
            anomalies.append({
                'type': '可疑爬虫活动',
                'count': len(self.stats['suspicious_activities']),
                'severity': 'medium'
            })
        
        return anomalies
    
    def get_analysis_summary(self) -> str:
        """获取分析摘要"""
        lines = []
        lines.append("【访问日志分析摘要】")
        lines.append("-" * 50)
        
        lines.append(f"总请求数: {self.stats['total_requests']:,}")
        lines.append(f"唯一IP数: {len(self.stats['unique_ips']):,}")
        
        if self.stats['top_paths']:
            top_path = self.stats['top_paths'].most_common(1)[0]
            lines.append(f"最热门路径: {top_path[0]} ({top_path[1]:,}次)")
        
        return "\n".join(lines)


def analyze_access_logs(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：分析访问日志"""
    analyzer = AccessLogAnalyzer(target_dir, timeout)
    return analyzer.analyze()
