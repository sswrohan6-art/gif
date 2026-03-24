# Run this directly: python verify_setup.py

def verify():
    results = []

    try:
        from PIL import Image
        results.append(("Pillow",       True,  Image.__version__))
    except ImportError as e:
        results.append(("Pillow",       False, str(e)))

    try:
        import numpy as np
        results.append(("NumPy",        True,  np.__version__))
    except ImportError as e:
        results.append(("NumPy",        False, str(e)))

    try:
        import sklearn
        results.append(("scikit-learn", True,  sklearn.__version__))
    except ImportError as e:
        results.append(("scikit-learn", False, str(e)))

    try:
        import scipy
        results.append(("SciPy",        True,  scipy.__version__))
    except ImportError as e:
        results.append(("SciPy",        False, str(e)))

    try:
        import matplotlib
        results.append(("Matplotlib",   True,  matplotlib.__version__))
    except ImportError as e:
        results.append(("Matplotlib",   False, str(e)))

    try:
        import pytest
        results.append(("pytest",       True,  pytest.__version__))
    except ImportError as e:
        results.append(("pytest",       False, str(e)))

    print("\n── Environment Check ──────────────────────")
    all_ok = True
    for name, ok, info in results:
        status = "✓" if ok else "✗"
        print(f"  {status}  {name:<15} {info}")
        if not ok:
            all_ok = False

    print("───────────────────────────────────────────")
    if all_ok:
        print("  All dependencies installed. Ready for Phase 3!\n")
    else:
        print("  Some packages missing. Re-run: pip install -r requirements.txt\n")

verify()
