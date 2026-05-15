# Server Forensic Analyzer v3.1

**服务器架构与服务取证分析工具**

自动分析服务器文件目录，识别服务配置、网络拓扑、安全态势、后端服务、数据库等，生成综合分析报告。

---

## 功能特性

### 核心分析模块（15项）

| 模块 | 功能 |
|------|------|
| **文件架构解析** | 分析目录结构，识别各目录角色（Web根目录、配置、日志、数据库等），生成架构层次图 |
| **服务配置分析** | 识别 Nginx/Apache/MySQL/PostgreSQL/Redis/MongoDB/Tomcat 等服务配置 |
| **Web反向代理** | 解析 Nginx/Apache 反向代理配置，提取 upstream、location、proxy_pass |
| **网络端口分析** | 分析监听端口、端口-服务映射、关键端口分类 |
| **IP关联分析** | 从访问日志提取 IP，统计访问频率，分类内外网 IP |
| **访问日志分析** | 解析 access.log，提取请求模式、UA 指纹、状态码分布、API 模式 |
| **后端服务发现** | 自动发现 gost/frp/xray/v2ray/shadowsocks 等后端服务 |
| **SSH安全评估** | 分析 auth.log，检测暴力破解、配置风险，生成安全建议 |
| **启动项分析** | 扫描 systemd/cron/supervisor/init.d/runit 等自启动配置 |
| **日志文件分析** | 内置日志字典，自动标注日志类型和用途，检测异常大小 |
| **数据库探测** | 探测 MySQL/PostgreSQL/MongoDB/Redis/SQLite 数据库 |
| **出站连接追踪** | 从防火墙日志、应用日志、配置文件中追踪对外连接 |
| **角色识别** | 综合判断服务器承担的角色（Web/数据库/代理/应用等） |
| **时间线分析** | 从日志中提取带时间戳的事件，生成时间线视图 |
| **关联分析** | 多数据源关联，构建完整服务架构图 |

### 其他特性

- **超时保护**：每个分析步骤都有超时机制，避免程序卡死
- **自动超时调整**：快速扫描目录后自动估算复杂度，调整超时时间
- **实时详情日志**：右侧详情栏实时显示各模块运行状态
- **图形界面**：浅蓝色主题，左右分栏布局，操作直观
- **命令行模式**：支持无头运行，适合服务器环境
- **综合报告**：包含所有分析结果的文本报告

---

## 项目结构

```
server-forensic-tool/
├── src/
│   ├── gui.py               # 图形界面主程序 v3.1
│   ├── main.py              # 命令行主程序
│   └── forensic_main.py     # 综合分析主程序
├── modules/
│   ├── file_structure_analyzer.py  # 文件架构解析
│   ├── service_config.py           # 服务配置分析
│   ├── web_proxy_analyzer.py       # Web反向代理解析
│   ├── network.py                  # 网络端口分析
│   ├── ip_analysis.py              # IP关联分析
│   ├── access_log_analyzer.py      # 访问日志分析
│   ├── backend_service_discovery.py # 后端服务发现
│   ├── ssh_security_analyzer.py    # SSH安全评估
│   ├── startup_analyzer.py         # 启动项扫描
│   ├── log_file_analyzer.py        # 日志文件标注
│   ├── database_detector.py        # 数据库探测
│   ├── outbound_tracker.py         # 出站连接追踪
│   ├── server_role.py              # 角色识别
│   ├── timeline_analyzer.py        # 时间线分析
│   ├── correlation_engine.py       # 关联分析引擎
│   ├── flowchart.py                # 架构流程图
│   ├── reporter.py                 # 报告生成
│   ├── task_estimator.py           # 任务量评估
│   └── utils.py                    # 工具函数（超时机制）
├── reports/                 # 报告输出目录
├── test_data/               # 测试数据
├── start.py                 # 统一启动脚本
└── README.md                # 本文件
```

---

## 使用方法

### 环境要求

- Python 3.8+
- tkinter（通常 Python 自带）

### 快速启动

```bash
# 启动图形界面
python start.py

# 或指定 --gui
python start.py --gui
```

### 命令行模式

```bash
# 分析指定目录
python start.py --cli /path/to/server/files

# 或直接指定目录
python start.py /path/to/server/files
```

### 查看帮助

```bash
python start.py -h
```

---

## 操作说明

1. **选择目录**：点击"浏览"选择要分析的服务器文件目录
2. **快速扫描**：系统自动扫描目录，估算复杂度并调整超时时间
3. **开始分析**：点击"开始分析"，右侧详情栏实时显示各模块运行状态
4. **查看报告**：分析完成后，报告自动保存到 `reports/` 文件夹

### 超时设置

- **自动调整**（默认）：根据目录复杂度自动设置超时时间
- **手动设置**：取消勾选"自动调整超时"，手动输入超时秒数

---

## 报告内容

生成的报告包含以下章节：

1. **执行摘要** — 关键发现概览
2. **文件架构解析** — 目录角色分布、架构层次、关键配置文件
3. **服务器角色识别** — 服务器承担的角色
4. **服务配置分析** — Web服务器、数据库、中间件
5. **Web反向代理配置** — 代理规则、upstream、location
6. **访问日志分析** — 请求统计、Top路径、UA、状态码
7. **后端服务发现** — 端口-进程-服务映射
8. **SSH安全评估** — 暴力破解检测、配置风险、安全建议
9. **启动项分析** — systemd/cron/supervisor 自启动项
10. **日志文件分析** — 日志类型标注、异常检测
11. **数据库服务探测** — 数据库类型、端口、状态
12. **出站连接追踪** — 对外连接目标、协议、来源
13. **网络与端口分析** — 端口-服务映射
14. **IP关联分析** — IP统计、内外网分类
15. **事件时间线** — 带时间戳的事件列表
16. **完整服务架构图** — 多层架构图、安全发现、数据覆盖评估

---

## 扩展开发

在 `modules/` 目录下添加新的分析模块：

1. 创建新的 `.py` 文件，实现分析类
2. 类中使用 `safe_execute` 包装耗时操作
3. 在 `gui.py` 的 `_run()` 方法中添加调用
4. 在 `reporter.py` 中添加对应的报告格式化方法

---

## 许可证

本项目仅供学习和研究使用。