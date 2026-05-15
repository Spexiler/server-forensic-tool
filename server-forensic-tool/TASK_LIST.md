# 服务器架构与服务分析工具 - 详细任务清单

## 项目概述
本工具专注于分析服务器的架构、服务配置、访问处理流程、重要应用程序、服务器角色以及重点IP关联关系。

## 核心任务

### 1. 项目基础建设
- [x] 创建项目文件夹结构
- [x] 重新设计项目架构
- [ ] 创建依赖管理文件 (requirements.txt)
- [ ] 创建 .gitignore 文件
- [ ] 创建主程序入口 (src/main.py)

### 2. 服务配置分析模块
- [ ] 创建 `modules/service_config.py`
- [ ] Apache 配置文件识别与解析
  - 查找 httpd.conf/apache2.conf
  - 提取监听端口 (Listen)
  - 提取虚拟主机配置 (VirtualHost)
  - 提取文档根目录 (DocumentRoot)
- [ ] Nginx 配置文件识别与解析
  - 查找 nginx.conf
  - 提取监听端口 (listen)
  - 提取 server 块配置
  - 提取 root 目录配置
- [ ] 数据库配置识别
  - MySQL (my.cnf/my.ini)
  - PostgreSQL (postgresql.conf)
  - MongoDB (mongod.conf)
  - Redis (redis.conf)
- [ ] 应用服务器配置识别
  - Tomcat (server.xml)
  - JBoss/WildFly 配置
- [ ] 服务启动脚本分析 (systemd/init.d)

### 3. 网络与端口分析模块
- [ ] 创建 `modules/network.py`
- [ ] 端口-服务映射表
- [ ] 从配置文件提取监听端口
- [ ] 分析 netstat/ss 输出（如果有）
- [ ] 识别重点服务端口 (80/443/22/3306/6379等)
- [ ] 端口与服务关联分析

### 4. 访问处理流程分析模块
- [ ] 创建 `modules/access_flow.py`
- [ ] Apache 访问日志分析
- [ ] Nginx 访问日志分析
- [ ] 反向代理配置识别
- [ ] 负载均衡配置识别
- [ ] 请求路由分析
- [ ] 访问流量模式统计

### 5. 服务器角色识别模块
- [ ] 创建 `modules/server_role.py`
- [ ] Web 服务器角色判定
- [ ] 数据库服务器角色判定
- [ ] 应用服务器角色判定
- [ ] 缓存服务器角色判定
- [ ] 网关/负载均衡器角色判定
- [ ] 混合角色场景分析
- [ ] 服务器角色综合报告

### 6. 重点IP关联分析模块
- [ ] 创建 `modules/ip_analysis.py`
- [ ] 访问日志 IP 提取
- [ ] IP 访问频率统计与排名
- [ ] 内部 IP 与外部 IP 分类
- [ ] IP 与服务关联分析
- [ ] IP 访问时间模式分析
- [ ] 重点 IP 列表生成

### 7. 重要应用程序识别模块
- [ ] 创建 `modules/apps.py`
- [ ] Web 应用识别 (WordPress/Drupal等)
- [ ] 应用程序路径定位
- [ ] 应用配置文件提取
- [ ] 应用依赖关系分析

### 8. 报告生成模块
- [ ] 创建 `modules/reporter.py`
- [ ] 创建 HTML 报告模板
- [ ] 创建文本报告模板
- [ ] 服务器架构拓扑报告
- [ ] 服务清单与配置报告
- [ ] 访问处理流程报告
- [ ] IP 关联分析报告
- [ ] 服务器角色分析报告

### 9. 配置文件
- [ ] 创建 `config/config.yaml`
- [ ] 定义服务配置路径规则
- [ ] 定义端口-服务映射
- [ ] 定义已知应用特征

### 10. 文档
- [ ] 创建 README.md
- [ ] 创建使用示例
- [ ] 创建 CHANGELOG.md

## 项目目录结构
```
server-forensic-tool/
├── src/
│   └── main.py                          # 主程序入口
├── modules/
│   ├── service_config.py               # 服务配置分析
│   ├── network.py                      # 网络端口分析
│   ├── access_flow.py                  # 访问处理分析
│   ├── server_role.py                  # 服务器角色识别
│   ├── ip_analysis.py                  # IP关联分析
│   ├── apps.py                         # 应用程序识别
│   └── reporter.py                     # 报告生成
├── reports/                            # 报告输出目录
├── templates/
│   ├── html_report.tpl                 # HTML报告模板
│   └── text_report.tpl                 # 文本报告模板
├── config/
│   └── config.yaml                     # 配置文件
├── data/                               # 数据目录
├── ARCHITECTURE.md                     # 架构文档
├── TASK_LIST.md                        # 任务清单
├── README.md                           # 使用文档
└── requirements.txt                    # 依赖列表
```

## 分析输出内容示例

### 服务器架构报告
- 服务器角色：Web + 应用服务器
- 运行的服务：Nginx, Tomcat, Redis
- 监听端口：80, 443, 8080, 6379

### 访问处理流程
- 用户 -> Nginx(80/443) -> Tomcat(8080) -> Redis(6379)
- 负载均衡：无
- 反向代理：Nginx 代理到 Tomcat

### 重点IP关联
- 内部数据库IP：192.168.1.100
- 管理访问IP：10.0.0.50
- 外部访问Top 5：...
