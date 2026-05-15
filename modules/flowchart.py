#!/usr/bin/env python3
"""
服务器架构流程图生成模块
生成ASCII格式的服务器架构和处理流程图
"""

from typing import Dict, List, Any, Tuple, Optional


class ArchitectureFlowchartGenerator:
    """架构流程图生成器"""
    
    # 组件图标
    ICONS = {
        'user': '👤',
        'firewall': '🔥',
        'loadbalancer': '⚖️',
        'web_server': '🌐',
        'app_server': '📦',
        'cache': '⚡',
        'database': '💾',
        'storage': '📁',
        'proxy': '🔄',
        'gateway': '🚪',
        'unknown': '❓',
    }
    
    # 箭头符号
    ARROW_H = '─'    # 水平线
    ARROW_V = '│'    # 垂直线
    ARROW_R = '→'    # 右箭头
    ARROW_L = '←'    # 左箭头
    ARROW_U = '↑'    # 上箭头
    ARROW_D = '↓'    # 下箭头
    CORNER_RD = '┌' # 右下角
    CORNER_RU = '└' # 右上角
    CORNER_LD = '┐' # 左下角
    CORNER_LU = '┘' # 左上角
    
    def __init__(self, services: Dict[str, Any], network: Dict[str, Any], 
                 roles: Dict[str, Any]):
        self.services = services
        self.network = network
        self.roles = roles
        self.components = []
        self.connections = []
    
    def generate(self) -> str:
        """生成完整的架构流程图"""
        self._analyze_components()
        self._analyze_connections()
        return self._build_flowchart()
    
    def _analyze_components(self):
        """分析并收集组件信息"""
        # 用户层（始终在最前端）
        self.components.append({
            'layer': 0,
            'type': 'user',
            'name': '外部用户',
            'details': '发起HTTP请求'
        })
        
        # 网络层 - 分析端口
        port_map = self.network.get('port_service_map', {})
        web_ports = []
        db_ports = []
        cache_ports = []
        
        for port, service in port_map.items():
            if service in ['HTTP', 'HTTPS', 'HTTP-Proxy', 'HTTPS-Alt']:
                web_ports.append(port)
            elif service in ['MySQL', 'PostgreSQL', 'MongoDB']:
                db_ports.append(port)
            elif service == 'Redis':
                cache_ports.append(port)
        
        # Web服务器层
        web_servers = self.services.get('web_servers', {})
        if web_servers:
            for server_type, info in web_servers.items():
                ports = info.get('listen_ports', web_ports)
                self.components.append({
                    'layer': 1,
                    'type': 'web_server',
                    'name': f'{server_type.upper()}',
                    'details': f'端口: {", ".join(map(str, ports[:3]))}'
                })
        elif web_ports:
            self.components.append({
                'layer': 1,
                'type': 'web_server',
                'name': 'Web服务器',
                'details': f'端口: {", ".join(map(str, web_ports[:3]))}'
            })
        
        # 中间件/应用服务器层
        middleware = self.services.get('middleware', {})
        if middleware:
            for mw_type, info in middleware.items():
                self.components.append({
                    'layer': 2,
                    'type': 'app_server',
                    'name': f'{mw_type.upper()}',
                    'details': '应用服务器'
                })
        
        # 缓存层
        if self.services.get('databases', {}).get('redis'):
            self.components.append({
                'layer': 3,
                'type': 'cache',
                'name': 'Redis',
                'details': f'端口: {", ".join(map(str, cache_ports)) or "6379"}'
            })
        
        # 数据库层
        databases = self.services.get('databases', {})
        if databases:
            for db_type, info in databases.items():
                if db_type != 'redis':  # Redis已在上层
                    db_port = port_map.get(db_ports[0] if db_ports else 3306, '')
                    self.components.append({
                        'layer': 4,
                        'type': 'database',
                        'name': f'{db_type.upper()}',
                        'details': f'端口: {db_port}'
                    })
        
        # 如果没有任何组件，添加默认
        if len(self.components) == 1:  # 只有用户
            self.components.append({
                'layer': 1,
                'type': 'unknown',
                'name': '未识别服务',
                'details': '请检查目录内容'
            })
    
    def _analyze_connections(self):
        """分析组件之间的连接关系"""
        # 基于组件层次自动生成连接
        layers = {}
        for comp in self.components:
            layer = comp['layer']
            if layer not in layers:
                layers[layer] = []
            layers[layer].append(comp)
        
        # 生成层间连接
        sorted_layers = sorted(layers.keys())
        for i in range(len(sorted_layers) - 1):
            current_layer = sorted_layers[i]
            next_layer = sorted_layers[i + 1]
            
            for comp in layers[current_layer]:
                for next_comp in layers[next_layer]:
                    self.connections.append((comp['name'], next_comp['name'], 'direct'))
    
    def _build_flowchart(self) -> str:
        """构建流程图"""
        lines = []
        
        # 标题
        lines.append("")
        lines.append("【服务器架构流程图】")
        lines.append("=" * 60)
        lines.append("")
        
        # 组件展示
        lines.append("组件层次:")
        lines.append("-" * 60)
        
        # 按层次分组显示
        layers = {}
        for comp in self.components:
            layer = comp['layer']
            if layer not in layers:
                layers[layer] = []
            layers[layer].append(comp)
        
        layer_names = {
            0: '用户层',
            1: 'Web层',
            2: '应用层',
            3: '缓存层',
            4: '数据层'
        }
        
        for layer_num in sorted(layers.keys()):
            layer_label = layer_names.get(layer_num, f'层{layer_num}')
            lines.append(f"\n  {layer_label}:")
            for comp in layers[layer_num]:
                icon = self.ICONS.get(comp['type'], '📌')
                lines.append(f"    {icon} {comp['name']}")
                if comp.get('details'):
                    lines.append(f"       └─ {comp['details']}")
        
        # 数据流向
        lines.append("\n" + "=" * 60)
        lines.append("【数据流向】")
        lines.append("-" * 60)
        lines.append("")
        lines.append(self._generate_flow_diagram())
        
        # 访问流程描述
        lines.append("\n" + "=" * 60)
        lines.append("【访问处理流程】")
        lines.append("-" * 60)
        lines.append("")
        lines.append(self._generate_process_description())
        
        return "\n".join(lines)
    
    def _generate_flow_diagram(self) -> str:
        """生成数据流向图"""
        lines = []
        
        # 创建简单的流程图
        flow_parts = []
        for comp in self.components:
            icon = self.ICONS.get(comp['type'], '📌')
            flow_parts.append(f"{icon}{comp['name']}")
        
        # 用箭头连接
        if len(flow_parts) > 1:
            diagram = "  " + f" {self.ARROW_R} ".join(flow_parts)
            lines.append(diagram)
        else:
            lines.append("  " + flow_parts[0] if flow_parts else "")
        
        # 添加详细连接
        lines.append("")
        lines.append("  连接关系:")
        for src, dst, conn_type in self.connections:
            lines.append(f"    {src} {self.ARROW_R} {dst}")
        
        return "\n".join(lines)
    
    def _generate_process_description(self) -> str:
        """生成处理流程描述"""
        lines = []
        
        descriptions = []
        
        # 描述入口
        if self.roles.get('summary', {}).get('active_roles'):
            roles = self.roles['summary']['active_roles']
            if 'web_server' in roles:
                descriptions.append("1. 用户通过HTTP/HTTPS访问Web服务器")
            if 'database_server' in roles:
                descriptions.append("2. 应用服务器处理业务逻辑并访问数据库")
            if 'cache_server' in roles:
                descriptions.append("3. 热点数据存储在缓存层加速访问")
        else:
            descriptions.append("1. 数据流向未确定，请检查配置")
        
        # 添加组件描述
        web_servers = self.services.get('web_servers', {})
        if web_servers:
            for server_type in web_servers.keys():
                if server_type == 'nginx':
                    descriptions.append(f"  - Nginx作为反向代理处理静态请求")
                elif server_type == 'apache':
                    descriptions.append(f"  - Apache提供Web服务")
        
        databases = self.services.get('databases', {})
        if databases:
            for db_type in databases.keys():
                if db_type == 'redis':
                    continue
                descriptions.append(f"  - {db_type.upper()}存储持久化数据")
        
        # 如果有缓存
        if databases.get('redis') or self.services.get('databases', {}).get('redis'):
            descriptions.append("  - Redis提供高速缓存服务")
        
        # 添加典型场景描述
        if web_servers and databases:
            descriptions.append("\n典型请求流程:")
            descriptions.append("  请求 → Nginx → 应用处理 → 数据库查询 → 响应")
            
            if databases.get('redis'):
                descriptions.append("  请求 → Nginx → 应用处理 → Redis缓存 → 响应")
        
        lines.extend(descriptions)
        
        return "\n".join(lines)
    
    def generate_simple_diagram(self) -> str:
        """生成简化流程图（单行）"""
        parts = []
        for comp in self.components:
            icon = self.ICONS.get(comp['type'], '●')
            parts.append(f"{icon}{comp['name']}")
        
        return f" → ".join(parts) if parts else "未检测到组件"


def generate_architecture_flowchart(services: Dict[str, Any], 
                                   network: Dict[str, Any],
                                   roles: Dict[str, Any]) -> str:
    """生成服务器架构流程图"""
    generator = ArchitectureFlowchartGenerator(services, network, roles)
    return generator.generate()


def generate_simple_architecture(services: Dict[str, Any],
                                 network: Dict[str, Any]) -> str:
    """生成简单架构描述"""
    parts = []
    
    # Web服务器
    if services.get('web_servers'):
        servers = list(services['web_servers'].keys())
        parts.append(f"Web({', '.join(servers)})")
    
    # 中间件
    if services.get('middleware'):
        mw = list(services['middleware'].keys())
        parts.append(f"应用({', '.join(mw)})")
    
    # 数据库
    if services.get('databases'):
        dbs = [k for k in services['databases'].keys() if k != 'redis']
        if dbs:
            parts.append(f"数据库({', '.join(dbs)})")
    
    # 缓存
    if services.get('databases', {}).get('redis'):
        parts.append("缓存(Redis)")
    
    return " | ".join(parts) if parts else "未检测到服务"
