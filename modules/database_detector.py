#!/usr/bin/env python3
"""
数据库服务探测模块 v2.0
探测MySQL、PostgreSQL、MongoDB等数据库
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from .utils import safe_execute


class DatabaseDetector:
    """数据库探测分析器"""
    
    def __init__(self, target_dir: str, timeout_seconds: int = 30):
        self.target_dir = Path(target_dir)
        self.timeout_seconds = timeout_seconds
        self.warnings = []
        self.databases = []
    
    def analyze(self) -> Dict[str, Any]:
        """执行数据库探测"""
        result, success, msg = safe_execute(
            self._do_analysis,
            timeout_seconds=self.timeout_seconds
        )
        
        if not success:
            self.warnings.append(f"数据库探测: {msg}")
        
        return {
            'data': {
                'databases': self.databases,
                'summary': {
                    'total': len(self.databases),
                    'types': list(set(db.get('type', 'unknown') for db in self.databases))
                }
            },
            'warnings': self.warnings
        }
    
    def _do_analysis(self):
        """执行分析"""
        self._detect_mysql()
        self._detect_postgresql()
        self._detect_mongodb()
        self._detect_redis()
        self._detect_sqlite()
    
    def _detect_mysql(self):
        """探测MySQL/MariaDB"""
        mysql_dirs = [
            Path('/var/lib/mysql/'),
            Path('/www/server/mysql/data/'),
            Path('/usr/local/mysql/data/'),
            Path('/opt/mysql/data/'),
        ]
        
        config_files = []
        for pattern in ['my.cnf', 'my.ini', '*.cnf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        my_cnf_locations = [
            Path('/etc/my.cnf'),
            Path('/etc/mysql/my.cnf'),
            Path('/etc/my.cnf.d/'),
        ]
        
        for loc in my_cnf_locations:
            if loc.exists():
                if loc.is_file():
                    config_files.append(loc)
                else:
                    config_files.extend(loc.glob('*.cnf'))
        
        for config_file in config_files:
            if 'mysql' in str(config_file).lower() or 'my' in str(config_file).lower():
                self._parse_mysql_config(config_file)
        
        for data_dir in mysql_dirs:
            if data_dir.exists():
                self._scan_mysql_data_dir(data_dir)
    
    def _parse_mysql_config(self, config_file: Path):
        """解析MySQL配置文件"""
        try:
            content = config_file.read_text(errors='ignore')
            
            info = {
                'type': 'mysql',
                'config_file': str(config_file),
                'status': 'unknown',
                'datadir': None,
                'port': 3306,
                'bind_address': None,
                'socket': None,
                'databases': []
            }
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'datadir':
                        info['datadir'] = value
                    elif key == 'port':
                        try:
                            info['port'] = int(value)
                        except:
                            pass
                    elif key == 'bind-address':
                        info['bind_address'] = value
                    elif key == 'socket':
                        info['socket'] = value
            
            if info['datadir']:
                info['status'] = 'configured'
                self._check_mysql_running(info)
                self._list_mysql_databases(info)
                
                if info not in self.databases:
                    self.databases.append(info)
        
        except Exception:
            pass
    
    def _check_mysql_running(self, info: Dict):
        """检查MySQL是否运行"""
        socket = info.get('socket')
        datadir = info.get('datadir')
        
        if socket:
            socket_path = Path(socket)
            if socket_path.exists():
                info['status'] = 'running'
        elif datadir:
            datadir_path = Path(datadir)
            if datadir_path.exists():
                info['status'] = 'stopped'
    
    def _list_mysql_databases(self, info: Dict):
        """列出MySQL数据库"""
        datadir = info.get('datadir')
        if not datadir:
            return
        
        datadir_path = Path(datadir)
        if not datadir_path.exists():
            return
        
        try:
            for item in datadir_path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    if item.name not in ['performance_schema', 'mysql', 'information_schema']:
                        info['databases'].append({
                            'name': item.name,
                            'path': str(item)
                        })
        except Exception:
            pass
    
    def _scan_mysql_data_dir(self, data_dir: Path):
        """扫描MySQL数据目录"""
        if not data_dir.exists():
            return
        
        existing = [db for db in self.databases if db['type'] == 'mysql']
        if existing:
            return
        
        info = {
            'type': 'mysql',
            'config_file': 'inferred',
            'status': 'unknown',
            'datadir': str(data_dir),
            'port': 3306,
            'databases': []
        }
        
        self._list_mysql_databases(info)
        
        if info['databases']:
            info['status'] = 'stopped'
            self.databases.append(info)
    
    def _detect_postgresql(self):
        """探测PostgreSQL"""
        pg_dirs = [
            Path('/var/lib/postgresql/'),
            Path('/www/server/postgresql/'),
            Path('/usr/local/pgsql/data/'),
            Path('/var/lib/pgsql/'),
        ]
        
        config_files = []
        for pattern in ['postgresql.conf', 'pg_hba.conf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        pg_conf_locations = [
            Path('/etc/postgresql/'),
            Path('/var/lib/postgresql/'),
        ]
        
        for pg_conf in pg_conf_locations:
            if pg_conf.exists():
                for conf in pg_conf.rglob('postgresql.conf'):
                    config_files.append(conf)
        
        for config_file in config_files:
            self._parse_postgresql_config(config_file)
        
        for data_dir in pg_dirs:
            if data_dir.exists():
                self._scan_postgresql_data_dir(data_dir)
    
    def _parse_postgresql_config(self, config_file: Path):
        """解析PostgreSQL配置"""
        try:
            content = config_file.read_text(errors='ignore')
            
            info = {
                'type': 'postgresql',
                'config_file': str(config_file),
                'status': 'unknown',
                'data_dir': None,
                'port': 5432,
                'bind_address': None,
                'databases': []
            }
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'data_directory':
                        info['data_dir'] = value
                    elif key == 'port':
                        try:
                            info['port'] = int(value)
                        except:
                            pass
                    elif key in ['listen_addresses', 'address']:
                        info['bind_address'] = value
            
            if info['data_dir']:
                info['status'] = 'configured'
                self.databases.append(info)
        
        except Exception:
            pass
    
    def _scan_postgresql_data_dir(self, data_dir: Path):
        """扫描PostgreSQL数据目录"""
        existing = [db for db in self.databases if db['type'] == 'postgresql']
        if existing:
            return
        
        if not data_dir.exists():
            return
        
        info = {
            'type': 'postgresql',
            'config_file': 'inferred',
            'status': 'unknown',
            'data_dir': str(data_dir),
            'port': 5432,
            'databases': []
        }
        
        self.databases.append(info)
    
    def _detect_mongodb(self):
        """探测MongoDB"""
        mongo_dirs = [
            Path('/var/lib/mongodb/'),
            Path('/www/server/mongodb/'),
            Path('/data/db/'),
            Path('/opt/mongodb/data/'),
        ]
        
        config_files = []
        for pattern in ['mongod.conf', 'mongodb.conf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        for config_file in config_files:
            self._parse_mongodb_config(config_file)
        
        for data_dir in mongo_dirs:
            if data_dir.exists():
                self._scan_mongodb_data_dir(data_dir)
    
    def _parse_mongodb_config(self, config_file: Path):
        """解析MongoDB配置"""
        try:
            content = config_file.read_text(errors='ignore')
            
            info = {
                'type': 'mongodb',
                'config_file': str(config_file),
                'status': 'unknown',
                'dbpath': None,
                'port': 27017,
                'bind_ip': None,
                'databases': []
            }
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower()
                        value = parts[1].strip()
                        
                        if key == 'dbpath':
                            info['dbpath'] = value
                        elif key == 'port':
                            try:
                                info['port'] = int(value)
                            except:
                                pass
                        elif key == 'bind_ip':
                            info['bind_ip'] = value
            
            if info['dbpath']:
                info['status'] = 'configured'
                self.databases.append(info)
        
        except Exception:
            pass
    
    def _scan_mongodb_data_dir(self, data_dir: Path):
        """扫描MongoDB数据目录"""
        existing = [db for db in self.databases if db['type'] == 'mongodb']
        if existing:
            return
        
        if not data_dir.exists():
            return
        
        info = {
            'type': 'mongodb',
            'config_file': 'inferred',
            'status': 'unknown',
            'dbpath': str(data_dir),
            'port': 27017,
            'databases': []
        }
        
        self.databases.append(info)
    
    def _detect_redis(self):
        """探测Redis"""
        config_files = []
        for pattern in ['redis.conf']:
            config_files.extend(self.target_dir.rglob(pattern))
        
        redis_conf_locations = [
            Path('/etc/redis/'),
            Path('/etc/'),
        ]
        
        for conf_dir in redis_conf_locations:
            if conf_dir.exists():
                for conf in conf_dir.glob('redis*.conf'):
                    config_files.append(conf)
        
        for config_file in config_files:
            self._parse_redis_config(config_file)
    
    def _parse_redis_config(self, config_file: Path):
        """解析Redis配置"""
        try:
            content = config_file.read_text(errors='ignore')
            
            info = {
                'type': 'redis',
                'config_file': str(config_file),
                'status': 'unknown',
                'dir': None,
                'port': 6379,
                'bind': None,
                'databases': []
            }
            
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'dir':
                        info['dir'] = value
                    elif key == 'port':
                        try:
                            info['port'] = int(value)
                        except:
                            pass
                    elif key == 'bind':
                        info['bind'] = value
            
            info['status'] = 'configured'
            self.databases.append(info)
        
        except Exception:
            pass
    
    def _detect_sqlite(self):
        """探测SQLite数据库"""
        sqlite_files = []
        
        for pattern in ['*.db', '*.sqlite', '*.sqlite3']:
            sqlite_files.extend(self.target_dir.rglob(pattern))
        
        for db_file in sqlite_files:
            if '__pycache__' not in str(db_file):
                self.databases.append({
                    'type': 'sqlite',
                    'config_file': 'N/A',
                    'status': 'file',
                    'path': str(db_file),
                    'name': db_file.name,
                    'size_mb': round(db_file.stat().st_size / (1024 * 1024), 2)
                })


def detect_databases(target_dir: str, timeout: int = 30) -> Dict[str, Any]:
    """便捷函数：探测数据库"""
    detector = DatabaseDetector(target_dir, timeout)
    return detector.analyze()
