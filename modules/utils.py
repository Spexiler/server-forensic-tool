#!/usr/bin/env python3
"""
工具函数模块 - 包含超时机制等
"""

import threading
from functools import wraps
from typing import Any, Callable, Tuple


class TimeoutException(Exception):
    """超时异常"""
    pass


def timeout(seconds: int = 30):
    """超时装饰器"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            result = [TimeoutException(f"Function {func.__name__} timed out after {seconds} seconds")]
            event = threading.Event()
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    result[0] = e
                finally:
                    event.set()
            
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            completed = event.wait(timeout=seconds)
            
            if not completed:
                raise TimeoutException(f"Function {func.__name__} timed out after {seconds} seconds")
            
            if isinstance(result[0], Exception):
                raise result[0]
            
            return result[0]
        return wrapper
    return decorator


def safe_execute(func: Callable, *args, timeout_seconds: int = 30, **kwargs) -> Tuple[Any, bool, str]:
    """
    安全执行函数，有超时和异常处理
    
    Returns:
        (result, success, message)
    """
    try:
        @timeout(timeout_seconds)
        def _exec():
            return func(*args, **kwargs)
        
        result = _exec()
        return (result, True, "Success")
    except TimeoutException as e:
        return (None, False, str(e))
    except Exception as e:
        return (None, False, f"Error: {str(e)}")
