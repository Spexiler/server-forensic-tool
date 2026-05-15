#!/usr/bin/env python3
"""
服务器角色识别模块
用于识别服务器承担的角色（Web服务器、数据库服务器、应用服务器等）
"""

from typing import Dict, List, Any


class ServerRoleIdentifier:
    """服务器角色识别器"""
    
    def __init__(self, service_data: Dict[str, Any], network_data: Dict[str, Any]):
        # 兼容新的数据结构（有'data'键或直接是数据）
        self.service_data = service_data.get('data', service_data) if isinstance(service_data, dict) else service_data
        self.network_data = network_data
        self.roles = {}
    
    def identify(self) -> Dict[str, Any]:
        """执行服务器角色识别"""
        self._check_web_server()
        self._check_database_server()
        self._check_application_server()
        self._check_cache_server()
        self._check_load_balancer()
        self._summarize_roles()
        return self.roles
    
    def _check_web_server(self):
        """检查是否为Web服务器"""
        is_web = False
        evidences = []
        
        # 检查是否有Web服务器配置
        if 'web_servers' in self.service_data:
            is_web = True
            web_servers = list(self.service_data['web_servers'].keys())
            evidences.append(f"发现Web服务器配置: {', '.join(web_servers)}")
        
        # 检查是否有Web服务端口
        critical_ports = self.network_data.get('critical_ports', {})
        if critical_ports.get('web'):
            is_web = True
            evidences.append(f"发现Web服务端口: {critical_ports['web']}")
        
        self.roles['web_server'] = {
            'is_role': is_web,
            'evidences': evidences,
            'confidence': 'high' if is_web else 'none'
        }
    
    def _check_database_server(self):
        """检查是否为数据库服务器"""
        is_db = False
        evidences = []
        
        # 检查数据库配置
        if 'databases' in self.service_data:
            is_db = True
            dbs = list(self.service_data['databases'].keys())
            evidences.append(f"发现数据库配置: {', '.join(dbs)}")
        
        # 检查数据库端口
        critical_ports = self.network_data.get('critical_ports', {})
        if critical_ports.get('database'):
            is_db = True
            evidences.append(f"发现数据库端口: {critical_ports['database']}")
        
        self.roles['database_server'] = {
            'is_role': is_db,
            'evidences': evidences,
            'confidence': 'high' if is_db else 'none'
        }
    
    def _check_application_server(self):
        """检查是否为应用服务器"""
        is_app = False
        evidences = []
        
        # 检查中间件
        if 'middleware' in self.service_data:
            is_app = True
            mw = list(self.service_data['middleware'].keys())
            evidences.append(f"发现中间件配置: {', '.join(mw)}")
        
        self.roles['application_server'] = {
            'is_role': is_app,
            'evidences': evidences,
            'confidence': 'high' if is_app else 'none'
        }
    
    def _check_cache_server(self):
        """检查是否为缓存服务器"""
        is_cache = False
        evidences = []
        
        # 检查Redis配置
        if 'databases' in self.service_data:
            if 'redis' in self.service_data['databases']:
                is_cache = True
                evidences.append("发现Redis缓存服务配置")
        
        self.roles['cache_server'] = {
            'is_role': is_cache,
            'evidences': evidences,
            'confidence': 'high' if is_cache else 'none'
        }
    
    def _check_load_balancer(self):
        """检查是否为负载均衡器"""
        is_lb = False
        evidences = []
        
        # 检查Nginx反向代理配置（简化判断）
        if 'web_servers' in self.service_data:
            if 'nginx' in self.service_data['web_servers']:
                # 这里可以更详细地检查upstream配置
                is_lb = False  # 先标记为否，需要更详细分析
                # evidences.append("发现Nginx，可能作为负载均衡器")
        
        self.roles['load_balancer'] = {
            'is_role': is_lb,
            'evidences': evidences,
            'confidence': 'medium' if is_lb else 'none'
        }
    
    def _summarize_roles(self):
        """汇总角色信息"""
        active_roles = []
        for role_name, role_info in self.roles.items():
            if role_info['is_role']:
                active_roles.append(role_name)
        
        self.roles['summary'] = {
            'active_roles': active_roles,
            'role_count': len(active_roles),
            'is_single_role': len(active_roles) == 1,
            'is_multi_role': len(active_roles) > 1
        }
    
    def get_role_summary(self) -> str:
        """获取角色摘要"""
        summary = []
        
        active_roles = self.roles.get('summary', {}).get('active_roles', [])
        
        if not active_roles:
            summary.append("未识别到明确的服务器角色")
            return "\n".join(summary)
        
        summary.append(f"服务器角色: {', '.join(active_roles)}")
        
        # 显示每个角色的证据
        for role_name in active_roles:
            role_info = self.roles.get(role_name, {})
            evidences = role_info.get('evidences', [])
            if evidences:
                summary.append(f"\n{role_name} 识别依据:")
                for evidence in evidences:
                    summary.append(f"  - {evidence}")
        
        return "\n".join(summary)
