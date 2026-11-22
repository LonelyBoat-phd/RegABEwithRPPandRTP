"""Optional leaf-stage timing. Parent totals are never sums of nested timers."""
from time import perf_counter
from contextlib import contextmanager


def measure(metrics, name, operation):
    if metrics is None:
        return operation()
    start = perf_counter()
    result = operation()
    metrics[name] = metrics.get(name, 0.0) + perf_counter() - start
    return result


@contextmanager
def stage(metrics, name):
    """Time one lexical stage, including rejection paths; never stores secrets."""
    if metrics is None:
        yield
        return
    start = perf_counter()
    try:
        yield
    finally:
        metrics[name] = metrics.get(name, 0.0) + perf_counter() - start


def account(metrics, total, prefixes, residual):
    """Account for mutually exclusive leaves under one independently timed parent."""
    leaves = sum(value for name, value in metrics.items()
                 if name not in (total, residual) and name.startswith(prefixes))
    remainder = metrics[total] - leaves
    if remainder < 0:
        raise ValueError(f'overlapping timing stages under {total}')
    metrics[residual] = remainder
