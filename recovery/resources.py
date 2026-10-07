"""Sample host and process-tree RAM; record CUDA allocator peaks separately."""
import threading
import time
import subprocess

import psutil


class ResourceMonitor:
    def __init__(self):
        self.stop_event = threading.Event()
        self.started = time.monotonic()
        self.peak_tree_rss = 0
        self.peak_host_used = 0
        self.min_host_available = psutil.virtual_memory().available
        self.peak_gpu_device_used_mib = None
        self.last_gpu_sample = -float('inf')
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self):
        process = psutil.Process()
        rss = 0
        for p in [process, *process.children(recursive=True)]:
            try:
                rss += p.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        memory = psutil.virtual_memory()
        self.peak_tree_rss = max(self.peak_tree_rss, rss)
        self.peak_host_used = max(self.peak_host_used, memory.total - memory.available)
        self.min_host_available = min(self.min_host_available, memory.available)
        if time.monotonic() - self.last_gpu_sample >= 2:
            self.last_gpu_sample = time.monotonic()
            try:
                value = subprocess.check_output(
                    ['nvidia-smi', '--query-gpu=memory.used', '--format=csv,noheader,nounits'],
                    text=True, stderr=subprocess.DEVNULL, timeout=1)
                used = max(float(v) for v in value.splitlines())
                self.peak_gpu_device_used_mib = max(self.peak_gpu_device_used_mib or 0, used)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass

    def _run(self):
        while not self.stop_event.wait(0.5):
            self._sample()

    def start(self):
        self._sample()
        self.thread.start()
        return self

    def finish(self):
        self._sample()
        self.stop_event.set()
        self.thread.join()
        return dict(elapsed_seconds=time.monotonic() - self.started,
                    peak_process_tree_rss_mib=self.peak_tree_rss / 2**20,
                    peak_host_used_mib=self.peak_host_used / 2**20,
                    minimum_host_available_mib=self.min_host_available / 2**20,
                    peak_gpu_device_used_mib=self.peak_gpu_device_used_mib,
                    gpu_device_sampling_interval_seconds=2,
                    ram_sampling_interval_seconds=0.5,
                    ram_note='Tree RSS can double-count shared pages; host used includes other applications.')
