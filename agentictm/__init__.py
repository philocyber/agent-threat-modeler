"""AgenticTM — Multi-agent Threat Modeling framework."""

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Monkey-patch: Pydantic v1 + Python 3.14 (PEP 649 deferred annotations)
# ---------------------------------------------------------------------------
# Python 3.14 defers annotation evaluation via __annotate_func__.
# Pydantic v1's ModelMetaclass.__new__ reads __annotations__ from the class
# namespace, which is empty under PEP 649.  This patch ensures the annotations
# are materialised before Pydantic v1 tries to read them.
# Affects chromadb.config.Settings (which uses pydantic.v1.BaseSettings).
# ---------------------------------------------------------------------------
import sys
import warnings

if sys.version_info >= (3, 14):
    # Suppress the noisy warning from langchain_core / pydantic v1 shim
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        message="Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.",
    )
    try:
        import pydantic.v1.main as _pv1_main

        _orig_meta_new = _pv1_main.ModelMetaclass.__new__

        def _patched_meta_new(mcs, name, bases, namespace, **kwargs):  # type: ignore[override]
            # If __annotations__ is empty but __annotate_func__ exists, call it
            ann = namespace.get("__annotations__", {})
            annotate_fn = namespace.get("__annotate_func__")
            if not ann and callable(annotate_fn):
                try:
                    namespace["__annotations__"] = annotate_fn(1)  # FORMAT_VALUE = 1
                except Exception:
                    pass
            return _orig_meta_new(mcs, name, bases, namespace, **kwargs)

        _pv1_main.ModelMetaclass.__new__ = _patched_meta_new  # type: ignore[assignment]
    except Exception:
        pass  # pydantic v1 shim not available — nothing to patch

