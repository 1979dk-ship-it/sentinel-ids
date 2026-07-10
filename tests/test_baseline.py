"""Unit tests for BaselineDetector.

Each test drives `_process` with packets carrying explicit timestamps. The helper
turns a list of per-interval counts into packets, sending a trailing packet in the
next interval so the last real bucket is finalized (buckets close lazily, when a
packet of a later interval arrives).
"""
import queue

from core.detectors.baseline import BaselineDetector


def _feed(det, src_ip, samples, t0=1000.0, interval=10):
    for i, count in enumerate(samples):
        base = t0 + i * interval
        for j in range(count):
            det._process({"src_ip": src_ip, "timestamp": base + j * 0.001})
    det._process({"src_ip": src_ip, "timestamp": t0 + len(samples) * interval})


def _drain(alerts):
    out = []
    while True:
        try:
            out.append(alerts.get_nowait())
        except queue.Empty:
            return out


def _detector(alerts, **kw):
    kw.setdefault("interval_seconds", 10)
    kw.setdefault("min_samples", 3)
    kw.setdefault("z_medium", 3.0)
    kw.setdefault("z_high", 5.0)
    return BaselineDetector(queue.Queue(), alerts, **kw)


def test_spike_after_learning_fires_high():
    alerts = queue.Queue()
    det = _detector(alerts)
    _feed(det, "10.0.0.5", [10, 11, 9, 10, 50])   # steady ~10, then a spike

    alert = alerts.get_nowait()
    assert alert.type == "BASELINE_ANOMALY"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "10.0.0.5"
    assert alert.details["observed"] == 50
    assert alerts.empty()


def test_no_alert_while_still_learning():
    alerts = queue.Queue()
    det = _detector(alerts, min_samples=5)
    _feed(det, "10.0.0.5", [10, 10, 500])   # only 3 samples, below min_samples

    assert alerts.empty()


def test_normal_variation_stays_silent():
    alerts = queue.Queue()
    det = _detector(alerts)
    _feed(det, "10.0.0.5", [10, 11, 9, 10, 11, 9])   # all within the learned spread

    assert alerts.empty()


def test_drop_below_baseline_does_not_alert():
    alerts = queue.Queue()
    det = _detector(alerts)
    _feed(det, "10.0.0.5", [100, 110, 90, 100, 10])   # last sample is a drop, not a spike

    assert alerts.empty()


def test_anomalous_sample_is_not_absorbed_into_baseline():
    alerts = queue.Queue()
    det = _detector(alerts)
    _feed(det, "10.0.0.5", [10, 11, 9, 10, 50, 50])   # two spikes in a row

    # If the first spike had been folded into the baseline it would have shifted;
    # because it is excluded, the baseline stays ~10 and the second spike fires too.
    assert len(_drain(alerts)) == 2


def test_baseline_is_per_ip():
    alerts = queue.Queue()
    det = _detector(alerts)
    _feed(det, "quiet", [2, 3, 2, 3, 500])            # 500 is a huge spike for a quiet host
    _feed(det, "busy",  [500, 510, 490, 505, 500])    # 500 is normal for a busy host

    fired = _drain(alerts)
    assert len(fired) == 1
    assert fired[0].src_ip == "quiet"


def test_missing_src_ip_is_ignored():
    alerts = queue.Queue()
    det = _detector(alerts)
    det._process({"src_ip": None, "timestamp": 1000.0})
    assert alerts.empty()


def test_learning_resumes_after_restore(session_factory):
    det1 = _detector(queue.Queue(), session_factory=session_factory)
    _feed(det1, "10.0.0.5", [10, 11, 9, 10])   # learn a baseline, no spike yet
    det1._flush(2000.0)                          # persist the learned state

    # a fresh detector restores that baseline and is immediately ready to detect
    alerts = queue.Queue()
    det2 = _detector(alerts, session_factory=session_factory)
    det2._restore()
    _feed(det2, "10.0.0.5", [50], t0=5000.0)     # a spike against the restored baseline

    alert = alerts.get_nowait()
    assert alert.type == "BASELINE_ANOMALY"
    assert alert.src_ip == "10.0.0.5"
