#!/usr/bin/env python3
"""
服务器架构与服务分析工具 - 启动脚本
支持GUI和命令行模式
"""

import sys
import os
from pathlib import Path


def print_help():
    """打印帮助信息"""
    print("服务器架构与服务分析工具")
    print("=" * 50)
    print("用法:")
    print("  python start.py [选项]")
    print()
    print("选项:")
    print("  --gui          启动图形界面（默认）")
    print("  --cli <目录>   命令行模式，分析指定目录")
    print("  -h, --help     显示此帮助信息")
    print()
    print("示例:")
    print("  python start.py")
    print("  python start.py --gui")
    print("  python start.py --cli /path/to/server/files")


def main():
    """主函数"""
    # 检查参数
    if len(sys.argv) == 1:
        # 无参数，默认启动GUI
        mode = 'gui'
    elif sys.argv[1] in ('-h', '--help'):
        print_help()
        return
    elif sys.argv[1] == '--gui':
        mode = 'gui'
    elif sys.argv[1] == '--cli':
        if len(sys.argv) < 3:
            print("错误: --cli 需要指定目录路径！")
            print()
            print_help()
            return
        mode = 'cli'
        target_dir = sys.argv[2]
    else:
        # 尝试将第一个参数作为目录，用CLI模式
        mode = 'cli'
        target_dir = sys.argv[1]
    
    # 导入并运行
    sys.path.insert(0, str(Path(__file__).parent))
    
    if mode == 'gui':
        print("启动图形界面...")
        try:
            from src.gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"错误: 无法导入GUI模块: {e}")
            print("请确保tkinter已正确安装。")
            return
    else:
        # CLI模式
        print("启动命令行模式...")
        try:
            from src.main import main as cli_main
            # 暂时修改sys.argv传递给main
            original_argv = sys.argv.copy()
            sys.argv = [sys.argv[0], target_dir]
            cli_main()
        except ImportError as e:
            print(f"错误: 无法导入CLI模块: {e}")
            return


if __name__ == "__main__":
    main()
