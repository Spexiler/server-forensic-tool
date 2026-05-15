#!/usr/bin/env python3
"""
服务器取证综合分析工具 v2.0
集成所有分析模块，从服务器文件目录中提取完整的服务架构信息
"""

import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.service_config import ServiceConfigAnalyzer
from modules.network import NetworkAnalyzer
from modules.ip_analysis import IPAnalyzer
from modules.server_role import ServerRoleIdentifier
from modules.reporter import ReportGenerator
from modules.flowchart import generate_architecture_flowchart
from modules.task_estimator import TaskEstimator
from modules.utils import safe_execute

from modules.web_proxy_analyzer import WebProxyAnalyzer
from modules.access_log_analyzer import AccessLogAnalyzer
from modules.backend_service_discovery import BackendServiceDiscovery
from modules.ssh_security_analyzer import SSHSecurityAnalyzer
from modules.startup_analyzer import StartupAnalyzer
from modules.log_file_analyzer import LogFileAnalyzer
from modules.database_detector import DatabaseDetector
from modules.outbound_tracker import OutboundConnectionTracker
from modules.timeline_analyzer import TimelineAnalyzer
from modules.correlation_engine import CorrelationEngine


class ForensicAnalyzer:
    """服务器取证综合分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.analysis_results = {}
        self.warnings = []
    
    def run_full_analysis(self) -> dict:
        """执行完整分析"""
        print("=" * 70)
        print("              服务器取证综合分析工具 v2.0")
        print("=" * 70)
        print(f"目标目录: {self.target_dir}")
        print(f"超时设置: {self.timeout_seconds}秒/步骤")
        print()
        
        # 阶段1: 基础分析
        self._run_basic_analysis()
        
        # 阶段2: 高级分析
        self._run_advanced_analysis()
        
        # 阶段3: 关联分析
        self._run_correlation_analysis()
        
        # 阶段4: 生成报告
        report_path = self._generate_report()
        
        print("\n" + "=" * 70)
        print("分析完成！")
        print(f"报告已保存至: {report_path}")
        print("=" * 70)
        
        return self.analysis_results
    
    def _run_basic_analysis(self):
        """基础分析"""
        print("\n" + "─" * 70)
        print("【阶段1: 基础分析】")
        print("─" * 70)
        
        # 1. 服务配置
        print("\n[1/4] 分析服务配置...")
        try:
            analyzer = ServiceConfigAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = analyzer.analyze()
            self.analysis_results['services'] = result['data']
            self._add_warnings(result.get('warnings', []))
            print(f"    ✓ 服务配置分析完成 (发现 {len(result['data']['summary']['search_status'])} 类服务)")
        except Exception as e:
            print(f"    ✗ 服务配置分析失败: {e}")
            self.analysis_results['services'] = {}
        
        # 2. 网络分析
        print("\n[2/4] 分析网络端口...")
        try:
            net_analyzer = NetworkAnalyzer(self.analysis_results.get('services', {}))
            network_data = net_analyzer.analyze()
            self.analysis_results['network'] = network_data
            print(f"    ✓ 网络分析完成")
        except Exception as e:
            print(f"    ✗ 网络分析失败: {e}")
            self.analysis_results['network'] = {}
        
        # 3. IP分析
        print("\n[3/4] 分析IP访问...")
        try:
            ip_analyzer = IPAnalyzer(str(self.target_dir), self.timeout_seconds)
            ip_result = ip_analyzer.analyze()
            self.analysis_results['ip'] = ip_result['data']
            self._add_warnings(result.get('warnings', []))
            print(f"    ✓ IP分析完成")
        except Exception as e:
            print(f"    ✗ IP分析失败: {e}")
            self.analysis_results['ip'] = {}
        
        # 4. 角色识别
        print("\n[4/4] 识别服务器角色...")
        try:
            role_id = ServerRoleIdentifier(
                self.analysis_results.get('services', {}),
                self.analysis_results.get('network', {})
            )
            roles_data = role_id.identify()
            self.analysis_results['roles'] = roles_data
            print(f"    ✓ 角色识别完成")
        except Exception as e:
            print(f"    ✗ 角色识别失败: {e}")
            self.analysis_results['roles'] = {}
    
    def _run_advanced_analysis(self):
        """高级分析"""
        print("\n" + "─" * 70)
        print("【阶段2: 高级分析】")
        print("─" * 70)
        
        # 1. Web代理配置解析
        print("\n[1/9] 解析Web反向代理配置...")
        try:
            proxy_analyzer = WebProxyAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = proxy_analyzer.analyze()
            self.analysis_results['web_proxy'] = result['data']
            self._add_warnings(result.get('warnings', []))
            proxy_count = len(result['data'].get('proxies', []))
            print(f"    ✓ 发现 {proxy_count} 个反向代理配置")
        except Exception as e:
            print(f"    ✗ Web代理解析失败: {e}")
            self.analysis_results['web_proxy'] = {}
        
        # 2. 访问日志分析
        print("\n[2/9] 分析Web访问日志...")
        try:
            log_analyzer = AccessLogAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = log_analyzer.analyze()
            self.analysis_results['access_log_analysis'] = result['data']
            self._add_warnings(result.get('warnings', []))
            total_req = result['data'].get('total_requests', 0)
            print(f"    ✓ 分析 {total_req} 条访问记录")
        except Exception as e:
            print(f"    ✗ 访问日志分析失败: {e}")
            self.analysis_results['access_log_analysis'] = {}
        
        # 3. 后端服务发现
        print("\n[3/9] 发现后端服务...")
        try:
            backend_discovery = BackendServiceDiscovery(str(self.target_dir), self.timeout_seconds)
            result = backend_discovery.analyze(self.analysis_results.get('web_proxy'))
            self.analysis_results['backend_services'] = result['data']
            self._add_warnings(result.get('warnings', []))
            service_count = result['data'].get('service_count', 0)
            print(f"    ✓ 发现 {service_count} 个后端服务")
        except Exception as e:
            print(f"    ✗ 后端服务发现失败: {e}")
            self.analysis_results['backend_services'] = {}
        
        # 4. SSH安全评估
        print("\n[4/9] 评估SSH安全态势...")
        try:
            ssh_analyzer = SSHSecurityAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = ssh_analyzer.analyze()
            self.analysis_results['ssh_security'] = result['data']
            self._add_warnings(result.get('warnings', []))
            failed = result['data'].get('failed_logins', 0)
            print(f"    ✓ SSH安全评估完成 (失败登录: {failed}次)")
        except Exception as e:
            print(f"    ✗ SSH安全评估失败: {e}")
            self.analysis_results['ssh_security'] = {}
        
        # 5. 启动项扫描
        print("\n[5/9] 扫描程序启动项...")
        try:
            startup_analyzer = StartupAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = startup_analyzer.analyze()
            self.analysis_results['startup_items'] = result['data']
            self._add_warnings(result.get('warnings', []))
            item_count = result['data'].get('summary', {}).get('total', 0)
            print(f"    ✓ 发现 {item_count} 个启动项")
        except Exception as e:
            print(f"    ✗ 启动项扫描失败: {e}")
            self.analysis_results['startup_items'] = {}
        
        # 6. 日志文件分析
        print("\n[6/9] 分析日志文件...")
        try:
            logfile_analyzer = LogFileAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = logfile_analyzer.analyze()
            self.analysis_results['log_files'] = result['data']
            self._add_warnings(result.get('warnings', []))
            file_count = result['data'].get('summary', {}).get('total_files', 0)
            anomaly_count = result['data'].get('anomaly_count', 0)
            print(f"    ✓ 发现 {file_count} 个日志文件 (异常: {anomaly_count}个)")
        except Exception as e:
            print(f"    ✗ 日志文件分析失败: {e}")
            self.analysis_results['log_files'] = {}
        
        # 7. 数据库探测
        print("\n[7/9] 探测数据库服务...")
        try:
            db_detector = DatabaseDetector(str(self.target_dir), self.timeout_seconds)
            result = db_detector.analyze()
            self.analysis_results['database_services'] = result['data']
            self._add_warnings(result.get('warnings', []))
            db_count = len(result['data'].get('databases', []))
            print(f"    ✓ 发现 {db_count} 个数据库")
        except Exception as e:
            print(f"    ✗ 数据库探测失败: {e}")
            self.analysis_results['database_services'] = {}
        
        # 8. 出站连接追踪
        print("\n[8/9] 追踪出站连接...")
        try:
            outbound_tracker = OutboundConnectionTracker(str(self.target_dir), self.timeout_seconds)
            result = outbound_tracker.analyze(
                self.analysis_results.get('web_proxy'),
                self.analysis_results.get('startup_items')
            )
            self.analysis_results['outbound_connections'] = result['data']
            self._add_warnings(result.get('warnings', []))
            conn_count = result['data'].get('summary', {}).get('total_connections', 0)
            print(f"    ✓ 发现 {conn_count} 条出站连接")
        except Exception as e:
            print(f"    ✗ 出站连接追踪失败: {e}")
            self.analysis_results['outbound_connections'] = {}
        
        # 9. 时间线分析
        print("\n[9/9] 生成事件时间线...")
        try:
            timeline_analyzer = TimelineAnalyzer(str(self.target_dir), self.timeout_seconds)
            result = timeline_analyzer.analyze(
                self.analysis_results.get('ssh_security'),
                self.analysis_results.get('access_log_analysis')
            )
            self.analysis_results['timeline'] = result['data']
            self._add_warnings(result.get('warnings', []))
            event_count = result['data'].get('total_events', 0)
            print(f"    ✓ 生成 {event_count} 个时间线事件")
        except Exception as e:
            print(f"    ✗ 时间线分析失败: {e}")
            self.analysis_results['timeline'] = {}
    
    def _run_correlation_analysis(self):
        """关联分析"""
        print("\n" + "─" * 70)
        print("【阶段3: 多数据源关联分析】")
        print("─" * 70)
        
        print("\n[*] 构建完整服务架构...")
        try:
            correlation_engine = CorrelationEngine()
            result = correlation_engine.analyze(
                web_proxy_data=self.analysis_results.get('web_proxy'),
                access_log_data=self.analysis_results.get('access_log_analysis'),
                backend_services=self.analysis_results.get('backend_services'),
                startup_items=self.analysis_results.get('startup_items'),
                ssh_security=self.analysis_results.get('ssh_security'),
                log_files=self.analysis_results.get('log_files'),
                database_services=self.analysis_results.get('database_services'),
                outbound_connections=self.analysis_results.get('outbound_connections'),
                services=self.analysis_results.get('services'),
                network=self.analysis_results.get('network')
            )
            
            self.analysis_results['full_architecture'] = result['data']['architecture']
            self.analysis_results['correlations'] = result['data']['correlations']
            
            arch_diagram = correlation_engine.generate_architecture_diagram()
            self.analysis_results['architecture_diagram'] = arch_diagram
            
            coverage = result['data']['architecture'].get('data_coverage', {})
            score = coverage.get('overall_score', 0)
            print(f"    ✓ 关联分析完成 (数据覆盖: {score:.0f}%)")
            
        except Exception as e:
            print(f"    ✗ 关联分析失败: {e}")
            self.analysis_results['full_architecture'] = {}
            self.analysis_results['correlations'] = []
    
    def _generate_report(self) -> str:
        """生成报告"""
        print("\n" + "─" * 70)
        print("【阶段4: 生成报告】")
        print("─" * 70)
        
        # 添加流程图
        if 'architecture_diagram' in self.analysis_results:
            self.analysis_results['flowchart'] = self.analysis_results['architecture_diagram']
        
        reporter = ReportGenerator()
        text_path = reporter.generate_text_report(self.analysis_results)
        
        print(f"\n    ✓ 报告已保存至: {text_path}")
        
        return text_path
    
    def _add_warnings(self, warnings: list):
        """添加警告"""
        if warnings:
            self.warnings.extend(warnings)
    
    def get_summary(self) -> str:
        """获取分析摘要"""
        lines = []
        lines.append("\n" + "=" * 70)
        lines.append("【分析摘要】")
        lines.append("=" * 70)
        
        # 角色
        roles = self.analysis_results.get('roles', {}).get('summary', {}).get('active_roles', [])
        lines.append(f"服务器角色: {', '.join(roles) if roles else '未识别'}")
        
        # 服务
        services = self.analysis_results.get('services', {})
        web_servers = list(services.get('web_servers', {}).keys())
        databases = list(services.get('databases', {}).keys())
        
        lines.append(f"Web服务: {', '.join(web_servers) if web_servers else '无'}")
        lines.append(f"数据库: {', '.join(databases) if databases else '无'}")
        
        # 反向代理
        proxies = self.analysis_results.get('web_proxy', {}).get('proxies', [])
        lines.append(f"反向代理: {len(proxies)}个")
        
        # SSH安全
        ssh = self.analysis_results.get('ssh_security', {})
        failed = ssh.get('failed_logins', 0)
        if failed > 100:
            lines.append(f"⚠️ SSH安全: {failed}次失败登录 (可能存在暴力破解)")
        elif failed > 0:
            lines.append(f"SSH安全: {failed}次失败登录")
        else:
            lines.append("SSH安全: 无异常")
        
        # 启动项
        startup = self.analysis_results.get('startup_items', {}).get('summary', {})
        tunnel_services = startup.get('tunnel_services', [])
        if tunnel_services:
            lines.append(f"⚠️ 发现 {len(tunnel_services)} 个隧道/代理服务")
        
        # 警告
        if self.warnings:
            lines.append(f"\n警告数: {len(self.warnings)}")
            for w in self.warnings[:5]:
                lines.append(f"  - {w[:80]}")
        
        return "\n".join(lines)


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python forensic_main.py <服务器文件目录>")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    
    if not Path(target_dir).exists():
        print(f"错误: 目录不存在: {target_dir}")
        sys.exit(1)
    
    analyzer = ForensicAnalyzer(target_dir)
    results = analyzer.run_full_analysis()
    
    # 打印摘要
    print(analyzer.get_summary())


if __name__ == "__main__":
    main()
