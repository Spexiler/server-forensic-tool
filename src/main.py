#!/usr/bin/env python3
"""
服务器架构与服务分析工具 - 主程序入口 (命令行模式)
"""

import sys
import os
from pathlib import Path

# 添加模块路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.service_config import ServiceConfigAnalyzer
from modules.network import NetworkAnalyzer
from modules.ip_analysis import IPAnalyzer
from modules.server_role import ServerRoleIdentifier
from modules.reporter import ReportGenerator


def main():
    """主函数"""
    print("=" * 60)
    print("服务器架构与服务分析工具")
    print("=" * 60)
    
    # 获取目标目录
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
    else:
        target_dir = input("请输入要分析的服务器文件目录路径: ").strip()
    
    target_path = Path(target_dir)
    if not target_path.exists():
        print(f"错误: 目录 '{target_dir}' 不存在！")
        sys.exit(1)
    
    if not target_path.is_dir():
        print(f"错误: '{target_dir}' 不是一个目录！")
        sys.exit(1)
    
    print(f"\n开始分析目录: {target_path.absolute()}")
    print("-" * 60)
    
    # 超时设置
    timeout_seconds = 30
    
    # 收集所有分析数据
    analysis_data = {
        'warnings': []
    }
    
    # 1. 服务配置分析
    print("\n[1/5] 分析服务配置...")
    try:
        service_analyzer = ServiceConfigAnalyzer(str(target_path), timeout_seconds)
        service_result = service_analyzer.analyze()
        analysis_data['services'] = service_result['data']
        if service_result.get('warnings'):
            for w in service_result['warnings']:
                print(f"  ⚠️ {w}")
                analysis_data['warnings'].append(w)
        print("  ✓ 服务配置分析完成")
    except Exception as e:
        print(f"  ✗ 服务配置分析失败: {e}")
        analysis_data['services'] = {}
        analysis_data['warnings'].append(f"服务配置分析: {e}")
    
    # 2. 网络与端口分析
    print("\n[2/5] 分析网络与端口...")
    try:
        network_analyzer = NetworkAnalyzer(analysis_data.get('services', {}))
        network_data = network_analyzer.analyze()
        analysis_data['network'] = network_data
        print("  ✓ 网络与端口分析完成")
    except Exception as e:
        print(f"  ✗ 网络与端口分析失败: {e}")
        analysis_data['network'] = {}
        analysis_data['warnings'].append(f"网络与端口分析: {e}")
    
    # 3. IP关联分析
    print("\n[3/5] 分析IP访问...")
    try:
        ip_analyzer = IPAnalyzer(str(target_path), timeout_seconds)
        ip_result = ip_analyzer.analyze()
        analysis_data['ip'] = ip_result['data']
        if ip_result.get('warnings'):
            for w in ip_result['warnings']:
                print(f"  ⚠️ {w}")
                analysis_data['warnings'].append(w)
        print("  ✓ IP关联分析完成")
    except Exception as e:
        print(f"  ✗ IP关联分析失败: {e}")
        analysis_data['ip'] = {}
        analysis_data['warnings'].append(f"IP关联分析: {e}")
    
    # 4. 服务器角色识别
    print("\n[4/5] 识别服务器角色...")
    try:
        role_identifier = ServerRoleIdentifier(
            analysis_data.get('services', {}),
            analysis_data.get('network', {})
        )
        roles_data = role_identifier.identify()
        analysis_data['roles'] = roles_data
        print("  ✓ 服务器角色识别完成")
    except Exception as e:
        print(f"  ✗ 服务器角色识别失败: {e}")
        analysis_data['roles'] = {}
        analysis_data['warnings'].append(f"服务器角色识别: {e}")
    
    # 5. 生成报告
    print("\n[5/5] 生成分析报告...")
    text_report_path = None
    json_report_path = None
    try:
        reporter = ReportGenerator()
        text_report_path = reporter.generate_text_report(analysis_data)
        json_report_path = reporter.generate_json_report(analysis_data)
        print("  ✓ 报告生成完成")
        print(f"\n文本报告: {text_report_path}")
        print(f"JSON报告: {json_report_path}")
    except Exception as e:
        print(f"  ✗ 报告生成失败: {e}")
    
    print("\n" + "=" * 60)
    print("分析完成！")
    print("=" * 60)
    
    if analysis_data.get('warnings'):
        print(f"\n共 {len(analysis_data['warnings'])} 个警告:")
        for w in analysis_data['warnings']:
            print(f"  - {w}")
    
    print("\n" + "-" * 60)
    # 输出摘要
    print("\n分析摘要:")
    print("-" * 40)
    
    if 'role_identifier' in locals():
        print(role_identifier.get_role_summary())
        print()
    
    if 'network_analyzer' in locals():
        print(network_analyzer.get_port_summary())
        print()
    
    if 'ip_analyzer' in locals():
        print(ip_analyzer.get_ip_summary())
        print()
    
    if text_report_path and json_report_path:
        print(f"\n报告已保存到:")
        print(f"  - 文本报告: {text_report_path}")
        print(f"  - JSON报告: {json_report_path}")


if __name__ == "__main__":
    main()
