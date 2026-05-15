#!/usr/bin/env python3
"""
报告生成模块 v2.0
增强版报告生成，支持多格式输出
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import sys


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, output_dir: str = None):
        # 强制使用项目的 reports 文件夹
        if output_dir is None:
            # 使用项目根目录下的 reports 文件夹
            script_dir = Path(__file__).parent.parent
            output_dir = script_dir / "reports"
        
        self.output_dir = Path(output_dir)
        
        # 确保目录存在
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            # 测试写入权限
            test_file = self.output_dir / ".test"
            test_file.write_text("test", encoding='utf-8')
            test_file.unlink()
        except (PermissionError, OSError) as e:
            print(f"警告: 无法创建 reports 目录: {e}")
            # 降级到临时目录
            import tempfile
            self.output_dir = Path(tempfile.gettempdir()) / "server_analysis_reports"
            self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_text_report(self, analysis_data: Dict[str, Any]) -> str:
        """生成增强文本格式报告"""
        report = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 标题
        report.append("=" * 70)
        report.append("                    服务器架构与服务分析报告")
        report.append("=" * 70)
        report.append(f"生成时间: {timestamp}")
        report.append("")
        
        # 显示警告
        warnings = analysis_data.get('warnings', [])
        if warnings:
            report.append("⚠️ 警告信息:")
            report.append("-" * 50)
            for w in warnings:
                report.append(f"  - {w}")
            report.append("")
        
        # 执行摘要
        report.append("【执行摘要】")
        report.append("-" * 50)
        summary = self._generate_summary(analysis_data)
        report.extend(summary)
        report.append("")
        
        # 服务器角色
        if 'roles' in analysis_data:
            report.append(self._format_roles_section(analysis_data['roles']))
            report.append("")
        
        # 服务配置（增强版）
        if 'services' in analysis_data:
            report.append(self._format_services_section(analysis_data['services']))
            report.append("")
        
        # Web服务器配置解析（新增）
        if 'web_proxy' in analysis_data:
            report.append(self._format_web_proxy_section(analysis_data['web_proxy']))
            report.append("")
        
        # 访问日志分析（新增）
        if 'access_log_analysis' in analysis_data:
            report.append(self._format_access_log_section(analysis_data['access_log_analysis']))
            report.append("")
        
        # 后端服务发现（新增）
        if 'backend_services' in analysis_data:
            report.append(self._format_backend_services_section(analysis_data['backend_services']))
            report.append("")
        
        # SSH安全评估（新增）
        if 'ssh_security' in analysis_data:
            report.append(self._format_ssh_security_section(analysis_data['ssh_security']))
            report.append("")
        
        # 启动项分析（新增）
        if 'startup_items' in analysis_data:
            report.append(self._format_startup_items_section(analysis_data['startup_items']))
            report.append("")
        
        # 日志文件分析（新增）
        if 'log_files' in analysis_data:
            report.append(self._format_log_files_section(analysis_data['log_files']))
            report.append("")
        
        # 数据库服务（新增）
        if 'database_services' in analysis_data:
            report.append(self._format_database_section(analysis_data['database_services']))
            report.append("")
        
        # 出站连接（新增）
        if 'outbound_connections' in analysis_data:
            report.append(self._format_outbound_section(analysis_data['outbound_connections']))
            report.append("")
        
        # 时间线（新增）
        if 'timeline' in analysis_data:
            report.append(self._format_timeline_section(analysis_data['timeline']))
            report.append("")
        
        # 网络信息
        if 'network' in analysis_data:
            report.append(self._format_network_section(analysis_data['network']))
            report.append("")
        
        # IP分析
        if 'ip' in analysis_data:
            report.append(self._format_ip_section(analysis_data['ip']))
            report.append("")
        
        # 文件架构分析（新增）
        if 'file_structure' in analysis_data:
            report.append(self._format_file_structure_section(analysis_data['file_structure']))
            report.append("")
        
        # 完整架构图（新增）
        if 'full_architecture' in analysis_data:
            report.append(self._format_full_architecture_section(analysis_data['full_architecture']))
            report.append("")
        
        # 关联分析图
        if 'architecture_diagram' in analysis_data:
            report.append(analysis_data['architecture_diagram'])
            report.append("")
        
        report.append("=" * 70)
        report.append("报告结束")
        report.append("=" * 70)
        
        report_text = "\n".join(report)
        
        # 保存报告
        filename = f"server_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_path = self.output_dir / filename
        output_path.write_text(report_text, encoding='utf-8')
        
        return str(output_path)
    
    def generate_json_report(self, analysis_data: Dict[str, Any]) -> str:
        """生成JSON格式报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"server_analysis_{timestamp}.json"
        output_path = self.output_dir / filename
        
        # 添加元数据
        output_data = {
            'generated_at': timestamp,
            'analysis_version': '2.0',
            'data': analysis_data
        }
        
        output_path.write_text(
            json.dumps(output_data, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        
        return str(output_path)
    
    def _generate_summary(self, analysis_data: Dict[str, Any]) -> List[str]:
        """生成执行摘要"""
        lines = []
        
        # 统计各项发现
        found_items = []
        
        if analysis_data.get('roles', {}).get('summary', {}).get('active_roles'):
            roles = analysis_data['roles']['summary']['active_roles']
            found_items.append(f"服务器角色: {', '.join(roles)}")
        
        if analysis_data.get('services', {}).get('web_servers'):
            servers = list(analysis_data['services']['web_servers'].keys())
            found_items.append(f"Web服务: {', '.join(servers)}")
        
        if analysis_data.get('services', {}).get('databases'):
            dbs = list(analysis_data['services']['databases'].keys())
            found_items.append(f"数据库: {', '.join(dbs)}")
        
        if analysis_data.get('web_proxy', {}).get('proxies'):
            proxy_count = len(analysis_data['web_proxy']['proxies'])
            found_items.append(f"反向代理规则: {proxy_count}条")
        
        if analysis_data.get('access_log_analysis', {}).get('total_requests', 0) > 0:
            total = analysis_data['access_log_analysis']['total_requests']
            found_items.append(f"访问日志记录: {total:,}条")
        
        if analysis_data.get('ssh_security', {}).get('failed_logins', 0) > 0:
            failed = analysis_data['ssh_security']['failed_logins']
            found_items.append(f"SSH失败登录: {failed}次")
        
        if analysis_data.get('backend_services', {}).get('services'):
            services = analysis_data['backend_services']['services']
            found_items.append(f"后端服务: {len(services)}个")
        
        for item in found_items:
            lines.append(f"  • {item}")
        
        if not found_items:
            lines.append("  未发现明显服务配置")
        
        return lines
    
    def _format_roles_section(self, roles_data: Dict[str, Any]) -> str:
        """格式化角色部分"""
        lines = []
        lines.append("【服务器角色识别】")
        lines.append("-" * 50)
        
        if 'summary' in roles_data:
            active_roles = roles_data['summary'].get('active_roles', [])
            if active_roles:
                lines.append(f"识别到的角色: {', '.join(active_roles)}")
            else:
                lines.append("未识别到明确角色")
        
        return "\n".join(lines)
    
    def _format_services_section(self, services_data: Dict[str, Any]) -> str:
        """格式化服务部分"""
        lines = []
        lines.append("【服务配置分析】")
        lines.append("-" * 50)
        
        # Web服务器
        if 'web_servers' in services_data and services_data['web_servers']:
            lines.append("Web服务器:")
            for server_type, server_info in services_data['web_servers'].items():
                lines.append(f"  - {server_type.upper()}")
                if isinstance(server_info, dict):
                    if 'listen_ports' in server_info:
                        lines.append(f"    监听端口: {server_info['listen_ports']}")
                    if 'document_roots' in server_info:
                        lines.append(f"    文档根目录: {server_info['document_roots'][:2]}")
        
        # 数据库
        if 'databases' in services_data and services_data['databases']:
            lines.append("数据库服务:")
            for db_type in services_data['databases'].keys():
                lines.append(f"  - {db_type}")
        
        # 中间件
        if 'middleware' in services_data and services_data['middleware']:
            lines.append("中间件:")
            for mw_type in services_data['middleware'].keys():
                lines.append(f"  - {mw_type}")
        
        if len(lines) <= 2:
            lines.append("未发现服务配置")
        
        return "\n".join(lines)
    
    def _format_web_proxy_section(self, proxy_data: Dict[str, Any]) -> str:
        """格式化Web反向代理配置"""
        lines = []
        lines.append("【Web反向代理配置】")
        lines.append("-" * 50)
        
        proxies = proxy_data.get('proxies', [])
        if not proxies:
            lines.append("  未发现反向代理配置")
            return "\n".join(lines)
        
        lines.append(f"发现 {len(proxies)} 条代理规则:")
        lines.append("")
        
        for i, proxy in enumerate(proxies, 1):
            lines.append(f"  [{i}] {proxy.get('server_name', '默认')}")
            lines.append(f"      监听端口: {proxy.get('listen_port', 'N/A')}")
            
            upstream = proxy.get('upstream', [])
            if upstream:
                lines.append(f"      代理目标:")
                for u in upstream[:3]:
                    lines.append(f"        - {u}")
                if len(upstream) > 3:
                    lines.append(f"        ... 共 {len(upstream)} 个目标")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_access_log_section(self, log_data: Dict[str, Any]) -> str:
        """格式化访问日志分析"""
        lines = []
        lines.append("【Web访问日志分析】")
        lines.append("-" * 50)
        
        total = log_data.get('total_requests', 0)
        lines.append(f"总请求数: {total:,}")
        
        if total == 0:
            lines.append("  未发现访问日志或无法解析")
            return "\n".join(lines)
        
        # Top路径
        top_paths = log_data.get('top_paths', [])[:5]
        if top_paths:
            lines.append("\n  Top 5 请求路径:")
            for path, count in top_paths:
                lines.append(f"    {count:>8,} | {path}")
        
        # Top UA
        top_ua = log_data.get('top_user_agents', [])[:5]
        if top_ua:
            lines.append("\n  Top 5 客户端(UA):")
            for ua, count in top_ua:
                ua_short = ua[:50] + "..." if len(ua) > 50 else ua
                lines.append(f"    {count:>8,} | {ua_short}")
        
        # 状态码分布
        status_codes = log_data.get('status_distribution', {})
        if status_codes:
            lines.append("\n  状态码分布:")
            for code in sorted(status_codes.keys(), key=lambda x: -status_codes[x])[:5]:
                count = status_codes[code]
                lines.append(f"    {code} - {count:,}次")
        
        return "\n".join(lines)
    
    def _format_backend_services_section(self, backend_data: Dict[str, Any]) -> str:
        """格式化后端服务发现"""
        lines = []
        lines.append("【后端服务自动发现】")
        lines.append("-" * 50)
        
        services = backend_data.get('services', [])
        if not services:
            lines.append("  未发现后端服务")
            return "\n".join(lines)
        
        lines.append(f"发现 {len(services)} 个后端服务:")
        lines.append("")
        
        for svc in services:
            port = svc.get('port', 'N/A')
            process = svc.get('process', '未知')
            config = svc.get('config_file', '未知')
            service_type = svc.get('type', '未知')
            
            lines.append(f"  端口 {port}: {service_type}")
            lines.append(f"    进程: {process}")
            lines.append(f"    配置: {config}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_ssh_security_section(self, ssh_data: Dict[str, Any]) -> str:
        """格式化SSH安全评估"""
        lines = []
        lines.append("【SSH安全态势评估】")
        lines.append("-" * 50)
        
        failed = ssh_data.get('failed_logins', 0)
        lines.append(f"失败登录尝试: {failed}次")
        
        if failed > 100:
            lines.append("  ⚠️ 警告: 检测到大量SSH失败登录，可能存在暴力破解")
        elif failed > 0:
            lines.append("  ⚠️ 注意: 检测到SSH失败登录")
        else:
            lines.append("  ✓ 未检测到异常登录")
        
        # Top攻击源
        top_attackers = ssh_data.get('top_attackers', [])[:5]
        if top_attackers:
            lines.append("\n  Top 5 攻击源IP:")
            for ip, count in top_attackers:
                lines.append(f"    {count:>6}次 | {ip}")
        
        # SSH配置检查
        ssh_config = ssh_data.get('ssh_config', {})
        if ssh_config:
            lines.append("\n  SSH配置检查:")
            if ssh_config.get('password_auth'):
                lines.append("    ⚠️ 允许密码认证(建议禁用)")
            if ssh_config.get('root_login'):
                lines.append("    ⚠️ 允许root登录(建议禁用)")
            if not ssh_config.get('password_auth') and not ssh_config.get('root_login'):
                lines.append("    ✓ SSH配置较为安全")
        
        return "\n".join(lines)
    
    def _format_startup_items_section(self, startup_data: Dict[str, Any]) -> str:
        """格式化启动项分析"""
        lines = []
        lines.append("【程序启动项与保活机制】")
        lines.append("-" * 50)
        
        items = startup_data.get('items', [])
        if not items:
            lines.append("  未发现自启动配置")
            return "\n".join(lines)
        
        lines.append(f"发现 {len(items)} 个自启动项:")
        lines.append("")
        
        for item in items[:10]:
            name = item.get('name', '未知')
            cmd = item.get('command', '未知')[:60]
            source = item.get('source', '未知')
            
            lines.append(f"  • {name}")
            lines.append(f"    命令: {cmd}...")
            lines.append(f"    来源: {source}")
            lines.append("")
        
        if len(items) > 10:
            lines.append(f"  ... 还有 {len(items) - 10} 个启动项")
        
        return "\n".join(lines)
    
    def _format_log_files_section(self, log_data: Dict[str, Any]) -> str:
        """格式化日志文件分析"""
        lines = []
        lines.append("【系统日志文件分析】")
        lines.append("-" * 50)
        
        files = log_data.get('files', [])
        if not files:
            lines.append("  未发现日志文件")
            return "\n".join(lines)
        
        anomalies = log_data.get('anomalies', [])
        
        lines.append(f"发现 {len(files)} 个日志文件")
        
        if anomalies:
            lines.append(f"\n  ⚠️ 异常日志(大小超限):")
            for anomaly in anomalies:
                lines.append(f"    {anomaly['file']}: {anomaly['size_mb']}MB")
        
        lines.append("\n  日志文件列表:")
        for log_file in files[:10]:
            size = log_file.get('size_mb', 0)
            desc = log_file.get('description', '未知')
            lines.append(f"    {size:>8.2f}MB | {log_file['path']}")
            lines.append(f"             | 用途: {desc}")
        
        return "\n".join(lines)
    
    def _format_database_section(self, db_data: Dict[str, Any]) -> str:
        """格式化数据库服务"""
        lines = []
        lines.append("【数据库服务探测】")
        lines.append("-" * 50)
        
        databases = db_data.get('databases', [])
        if not databases:
            lines.append("  未发现数据库服务")
            return "\n".join(lines)
        
        for db in databases:
            db_type = db.get('type', '未知')
            status = db.get('status', 'unknown')
            data_dir = db.get('data_dir', '未知')
            port = db.get('port', 'N/A')
            
            status_icon = "✓" if status == "running" else "✗"
            lines.append(f"  {status_icon} {db_type.upper()}")
            lines.append(f"      状态: {status}")
            lines.append(f"      数据目录: {data_dir}")
            lines.append(f"      端口: {port}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_outbound_section(self, outbound_data: Dict[str, Any]) -> str:
        """格式化出站连接"""
        lines = []
        lines.append("【出站连接追踪】")
        lines.append("-" * 50)
        
        connections = outbound_data.get('connections', [])
        if not connections:
            lines.append("  未发现出站连接记录")
            return "\n".join(lines)
        
        lines.append(f"发现 {len(connections)} 条出站连接:")
        lines.append("")
        
        for conn in connections[:10]:
            target = conn.get('target', '未知')
            port = conn.get('port', 'N/A')
            protocol = conn.get('protocol', 'TCP')
            source = conn.get('source', '未知')
            
            lines.append(f"  → {target}:{port} ({protocol})")
            lines.append(f"    来源: {source}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_timeline_section(self, timeline_data: Dict[str, Any]) -> str:
        """格式化时间线"""
        lines = []
        lines.append("【事件时间线】")
        lines.append("-" * 50)
        
        events = timeline_data.get('events', [])
        if not events:
            lines.append("  未提取到时间线事件")
            return "\n".join(lines)
        
        lines.append(f"提取到 {len(events)} 个事件:")
        lines.append("")
        
        for event in events[:20]:
            timestamp = event.get('timestamp', '未知时间')
            category = event.get('category', '其他')
            message = event.get('message', '')[:50]
            
            lines.append(f"  [{timestamp}] [{category}]")
            if message:
                lines.append(f"    {message}")
        
        return "\n".join(lines)
    
    def _format_network_section(self, network_data: Dict[str, Any]) -> str:
        """格式化网络部分"""
        lines = []
        lines.append("【网络与端口分析】")
        lines.append("-" * 50)
        
        if 'port_service_map' in network_data:
            lines.append("端口-服务映射:")
            for port, service in sorted(network_data['port_service_map'].items()):
                lines.append(f"  - {port}: {service}")
        
        if 'critical_ports' in network_data:
            critical = network_data['critical_ports']
            if critical.get('web'):
                lines.append(f"\nWeb服务端口: {critical['web']}")
            if critical.get('database'):
                lines.append(f"数据库端口: {critical['database']}")
        
        return "\n".join(lines)
    
    def _format_ip_section(self, ip_data: Dict[str, Any]) -> str:
        """格式化IP部分"""
        lines = []
        lines.append("【IP关联分析】")
        lines.append("-" * 50)
        
        lines.append(f"发现IP总数: {len(ip_data.get('all_ips', []))}")
        lines.append(f"内网IP: {len(ip_data.get('internal_ips', []))}")
        lines.append(f"外网IP: {len(ip_data.get('external_ips', []))}")
        
        top_ips = ip_data.get('top_ips', [])
        if top_ips:
            lines.append("\nTop 5 访问IP:")
            for i, (ip, count) in enumerate(top_ips[:5], 1):
                ip_type = "内网" if ip in ip_data.get('internal_ips', []) else "外网"
                lines.append(f"  {i}. {ip} ({ip_type}): {count}次")
        
        return "\n".join(lines)
    
    def _format_full_architecture_section(self, arch_data: Dict[str, Any]) -> str:
        """格式化完整架构图"""
        lines = []
        lines.append("【完整服务架构图】")
        lines.append("=" * 50)
        
        # 生成ASCII架构图
        lines.append("")
        lines.append("  外部客户端")
        lines.append("       ↓")
        
        # 入口
        entry = arch_data.get('entry', [])
        if entry:
            for e in entry[:2]:
                lines.append(f"  {e.get('listen', 'N/A')}端口 ({e.get('type', 'Web')})")
            lines.append("       ↓")
        
        # 代理层
        proxies = arch_data.get('proxies', [])
        if proxies:
            lines.append("  反向代理层")
            for p in proxies[:3]:
                lines.append(f"    → {p.get('target', 'N/A')}:{p.get('port', 'N/A')}")
            lines.append("       ↓")
        
        # 后端服务
        backends = arch_data.get('backends', [])
        if backends:
            lines.append("  后端服务")
            for b in backends[:5]:
                lines.append(f"    • {b.get('type', '服务')} ({b.get('port', 'N/A')})")
            lines.append("       ↓")
        
        # 数据层
        databases = arch_data.get('databases', [])
        if databases:
            lines.append("  数据层")
            for db in databases[:3]:
                lines.append(f"    • {db.get('type', 'DB')} ({db.get('port', 'N/A')})")
        
        # 架构层次
        layers = arch_data.get('layers', [])
        if layers:
            lines.append("\n【架构层次】")
            for layer in layers:
                layer_name = layer.get('name', '')
                layer_type = layer.get('type', '')
                components = layer.get('components', [])
                lines.append(f"\n  {layer_name} [{layer_type}]:")
                for comp in components[:5]:
                    name = comp.get('name', 'Unknown')
                    lines.append(f"    • {name}")
        
        # 安全发现
        security_findings = arch_data.get('security_findings', [])
        if security_findings:
            lines.append("\n【安全发现】")
            for finding in security_findings:
                severity = finding.get('severity', 'info')
                icon = "🔴" if severity in ['high', 'critical'] else "🟡"
                lines.append(f"  {icon} {finding.get('description', '')}")
        
        lines.append("")
        lines.append("=" * 50)
        
        return "\n".join(lines)
    
    def _format_file_structure_section(self, file_struct: Dict[str, Any]) -> str:
        """格式化文件架构分析"""
        lines = []
        lines.append("【文件架构解析】")
        lines.append("-" * 50)
        
        # 统计信息
        total_files = file_struct.get('total_files', 0)
        total_dirs = file_struct.get('total_dirs', 0)
        total_size_mb = file_struct.get('total_size', 0) / (1024 * 1024)
        
        lines.append(f"\n📊 目录统计:")
        lines.append(f"  • 文件总数: {total_files:,}")
        lines.append(f"  • 目录总数: {total_dirs:,}")
        lines.append(f"  • 总大小: {total_size_mb:.2f} MB")
        
        # 目录角色分布
        role_dist = file_struct.get('role_distribution', {})
        if role_dist:
            lines.append(f"\n📁 目录角色分布:")
            role_descriptions = {
                'web_root': 'Web根目录',
                'web_app': 'Web应用程序',
                'config': '配置文件',
                'log': '日志文件',
                'database': '数据库文件',
                'cache': '缓存目录',
                'static_resource': '静态资源',
                'backend_service': '后端服务',
                'security': '安全相关',
                'system': '系统配置',
                'backup': '备份文件',
                'user_content': '用户内容',
                'proxy_config': '代理配置',
                'container': '容器配置',
                'monitoring': '监控相关'
            }
            for role, count in sorted(role_dist.items(), key=lambda x: -x[1])[:8]:
                desc = role_descriptions.get(role, role)
                lines.append(f"  • {desc}: {count} 个")
        
        # 架构层次
        layers = file_struct.get('architecture_layers', [])
        if layers:
            lines.append(f"\n🏗️ 架构层次:")
            for layer in layers:
                layer_name = layer.get('name', '')
                count = layer.get('count', 0)
                dirs = layer.get('directories', [])
                lines.append(f"\n  {layer_name} ({count}个):")
                for d in dirs[:3]:
                    path = d.get('path', '')
                    if len(path) > 40:
                        path = '...' + path[-37:]
                    lines.append(f"    📂 {path}")
        
        # 关键文件
        important_paths = file_struct.get('important_paths', [])
        if important_paths:
            lines.append(f"\n🔑 关键配置文件:")
            for imp in important_paths[:10]:
                path = imp.get('path', '')
                imp_type = imp.get('type', '')
                if len(path) > 50:
                    path = '...' + path[-47:]
                lines.append(f"  • {path}")
                lines.append(f"      └─ {imp_type}")
        
        return "\n".join(lines)
