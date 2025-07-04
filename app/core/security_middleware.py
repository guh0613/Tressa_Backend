"""
安全中间件和工具函数
包括速率限制、内容验证、XSS防护等
"""
import time
import hashlib
from typing import Dict, Optional
from collections import defaultdict, deque
from fastapi import Request, HTTPException, status
from fastapi.responses import Response
import re
import html


class RateLimiter:
    """简单的内存速率限制器"""
    
    def __init__(self):
        # 存储每个IP的请求时间戳
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
        # 不同端点的限制配置
        self.limits = {
            "public_read": {"requests": 100, "window": 3600},  # 每小时100次
            "raw_content": {"requests": 200, "window": 3600},  # 每小时200次
            "default": {"requests": 1000, "window": 3600},     # 默认每小时1000次
        }
    
    def is_allowed(self, client_ip: str, endpoint_type: str = "default") -> bool:
        """检查是否允许请求"""
        now = time.time()
        limit_config = self.limits.get(endpoint_type, self.limits["default"])
        window = limit_config["window"]
        max_requests = limit_config["requests"]
        
        # 获取该IP的请求队列
        request_times = self.requests[client_ip]
        
        # 清理过期的请求记录
        while request_times and request_times[0] < now - window:
            request_times.popleft()
        
        # 检查是否超过限制
        if len(request_times) >= max_requests:
            return False
        
        # 记录当前请求
        request_times.append(now)
        return True
    
    def get_remaining_requests(self, client_ip: str, endpoint_type: str = "default") -> int:
        """获取剩余请求次数"""
        now = time.time()
        limit_config = self.limits.get(endpoint_type, self.limits["default"])
        window = limit_config["window"]
        max_requests = limit_config["requests"]
        
        request_times = self.requests[client_ip]
        
        # 清理过期的请求记录
        while request_times and request_times[0] < now - window:
            request_times.popleft()
        
        return max(0, max_requests - len(request_times))


# 全局速率限制器实例
rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """获取客户端真实IP地址"""
    # 检查代理头
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # 取第一个IP（最原始的客户端IP）
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # 回退到直接连接IP
    return request.client.host if request.client else "unknown"


def check_rate_limit(request: Request, endpoint_type: str = "default") -> None:
    """检查速率限制，如果超限则抛出异常"""
    client_ip = get_client_ip(request)
    
    if not rate_limiter.is_allowed(client_ip, endpoint_type):
        remaining = rate_limiter.get_remaining_requests(client_ip, endpoint_type)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
            headers={
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(int(time.time() + 3600)),
                "Retry-After": "3600"
            }
        )


def sanitize_content(content: str) -> str:
    """清理内容，防止XSS攻击"""
    if not content:
        return content
    
    # HTML转义
    content = html.escape(content)
    
    # 移除潜在的脚本标签（即使已经转义，也要额外小心）
    script_pattern = re.compile(r'&lt;script.*?&gt;.*?&lt;/script&gt;', re.IGNORECASE | re.DOTALL)
    content = script_pattern.sub('', content)
    
    return content


def validate_content_type(language: str, content: str) -> bool:
    """验证内容类型是否与声明的语言匹配"""
    if not language or not content:
        return True
    
    # 基本的内容验证规则
    validation_rules = {
        "javascript": [r'function\s+\w+', r'var\s+\w+', r'const\s+\w+', r'let\s+\w+'],
        "python": [r'def\s+\w+', r'import\s+\w+', r'from\s+\w+', r'class\s+\w+'],
        "java": [r'public\s+class', r'private\s+\w+', r'public\s+\w+'],
        "html": [r'<html', r'<head', r'<body', r'<div'],
        "css": [r'\w+\s*{', r':\s*\w+;', r'@media'],
        "json": [r'^\s*{', r'^\s*\['],
        "sql": [r'SELECT\s+', r'INSERT\s+', r'UPDATE\s+', r'DELETE\s+'],
    }
    
    rules = validation_rules.get(language.lower(), [])
    if not rules:
        return True  # 未知语言类型，允许通过
    
    # 检查是否至少匹配一个规则
    for rule in rules:
        if re.search(rule, content, re.IGNORECASE):
            return True
    
    return False


def add_security_headers(response: Response) -> None:
    """添加安全响应头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # 对于raw content，添加额外的安全头
    if "text/" in response.headers.get("Content-Type", ""):
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"


def generate_etag(content: str) -> str:
    """生成ETag用于缓存控制"""
    return hashlib.md5(content.encode('utf-8')).hexdigest()


def check_if_none_match(request: Request, etag: str) -> bool:
    """检查If-None-Match头，用于缓存验证"""
    if_none_match = request.headers.get("If-None-Match")
    if if_none_match:
        # 移除引号
        if_none_match = if_none_match.strip('"')
        return if_none_match == etag
    return False
