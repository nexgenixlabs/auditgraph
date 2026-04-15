"""
Phase 68: In-memory metrics collector for API performance tracking.

Thread-safe counters and deques for request latency, error rates,
and per-endpoint statistics. Exposes Prometheus text exposition format.
"""
import time
import threading
from collections import deque, defaultdict


class MetricsCollector:
    """Thread-safe in-memory metrics for API performance tracking."""
    _instance = None
    _init_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.status_counts = defaultdict(int)
        self.latencies = deque(maxlen=1000)
        self.endpoint_latencies = defaultdict(lambda: deque(maxlen=100))
        self.endpoint_counts = defaultdict(int)

    @classmethod
    def get(cls):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def record_request(self, method, path, status_code, duration_ms):
        with self._lock:
            self.request_count += 1
            self.status_counts[status_code] += 1
            if status_code >= 400:
                self.error_count += 1
            self.latencies.append(duration_ms)
            key = f"{method} {path}"
            self.endpoint_latencies[key].append(duration_ms)
            self.endpoint_counts[key] += 1

    def get_summary(self):
        with self._lock:
            lats = sorted(self.latencies)
            uptime = time.time() - self.start_time
            return {
                'uptime_seconds': round(uptime),
                'total_requests': self.request_count,
                'total_errors': self.error_count,
                'error_rate': round(self.error_count / max(self.request_count, 1) * 100, 2),
                'avg_latency_ms': round(sum(lats) / len(lats), 1) if lats else 0,
                'p95_latency_ms': round(lats[min(int(len(lats) * 0.95), len(lats) - 1)] if lats else 0, 1),
                'p99_latency_ms': round(lats[min(int(len(lats) * 0.99), len(lats) - 1)] if lats else 0, 1),
                'status_codes': dict(self.status_counts),
            }

    def get_top_endpoints(self, n=10):
        with self._lock:
            sorted_eps = sorted(self.endpoint_counts.items(), key=lambda x: -x[1])[:n]
            result = []
            for ep, count in sorted_eps:
                lats = list(self.endpoint_latencies[ep])
                result.append({
                    'endpoint': ep,
                    'count': count,
                    'avg_ms': round(sum(lats) / len(lats), 1) if lats else 0,
                })
            return result

    def prometheus_format(self):
        """Return metrics in Prometheus text exposition format."""
        lines = []
        s = self.get_summary()

        lines.append('# HELP auditgraph_uptime_seconds Platform uptime in seconds')
        lines.append('# TYPE auditgraph_uptime_seconds gauge')
        lines.append(f'auditgraph_uptime_seconds {s["uptime_seconds"]}')

        lines.append('# HELP auditgraph_requests_total Total HTTP requests')
        lines.append('# TYPE auditgraph_requests_total counter')
        lines.append(f'auditgraph_requests_total {s["total_requests"]}')

        lines.append('# HELP auditgraph_errors_total Total HTTP errors (4xx+5xx)')
        lines.append('# TYPE auditgraph_errors_total counter')
        lines.append(f'auditgraph_errors_total {s["total_errors"]}')

        lines.append('# HELP auditgraph_latency_avg_ms Average response latency')
        lines.append('# TYPE auditgraph_latency_avg_ms gauge')
        lines.append(f'auditgraph_latency_avg_ms {s["avg_latency_ms"]}')

        lines.append('# HELP auditgraph_latency_p95_ms P95 response latency')
        lines.append('# TYPE auditgraph_latency_p95_ms gauge')
        lines.append(f'auditgraph_latency_p95_ms {s["p95_latency_ms"]}')

        lines.append('# HELP auditgraph_http_status HTTP responses by status code')
        lines.append('# TYPE auditgraph_http_status counter')
        for code, count in s['status_codes'].items():
            lines.append(f'auditgraph_http_status{{code="{code}"}} {count}')

        try:
            import psutil
            proc = psutil.Process()
            lines.append('# HELP auditgraph_memory_rss_bytes RSS memory usage')
            lines.append('# TYPE auditgraph_memory_rss_bytes gauge')
            lines.append(f'auditgraph_memory_rss_bytes {proc.memory_info().rss}')
            lines.append('# HELP auditgraph_cpu_percent CPU usage percent')
            lines.append('# TYPE auditgraph_cpu_percent gauge')
            lines.append(f'auditgraph_cpu_percent {proc.cpu_percent()}')
        except ImportError:
            pass

        return '\n'.join(lines) + '\n'
