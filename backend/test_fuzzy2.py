import sys, os
sys.path.insert(0, '.')
from modules.fuzzy_hash import run_fuzzy_hash

tests = [
    {
        "name": "Mozi exact match",
        "ssdeep": "3072:phNlHuBafLeBtfCzpta8xlBIOeVo3/4sxLJ10xioP:p3lOYoaja8xzxe0wsxzSi2",
        "sha256": "22ea54360f7b59f926660f70b05b11f6b00bc1519b5114df06176d0c53003e24"
    },
    {
        "name": "Mirai exact match",
        "ssdeep": "3072:FzySSvodcHTgnM1sCPSJ8epvrzTXE7yAmv:cSSvyNM1sCPSiCvTU7yAmv",
        "sha256": "31523d704bdebe4be4a6bed20ae517721328f9605d63be633e9c2b68750b7aaf"
    },
    {
        "name": "Mozi mutated variant",
        "ssdeep": "3072:phNlHuBafLeBtfCzpta8xlBIOeVo3/4sxLJ10xioX:p3lOYoaja8xzxe0wsxzSi9",
        "sha256": ""
    },
    {
        "name": "Mirai mutated variant",
        "ssdeep": "3072:FzySSvodcHTgnM1sCPSJ8epvrzTXE7yBmv:cSSvyNM1sCPSiCvTU7yBmv",
        "sha256": ""
    },
]

print("=" * 65)
print(f"  {'TEST':<30} {'SCORE':<8} {'FAMILY':<10} LABEL")
print("=" * 65)
for t in tests:
    r = run_fuzzy_hash(t["ssdeep"], t["sha256"])
    best = r.get("best_match") or {}
    print(f"  {t['name']:<30} {r['top_score']:<8} {r['top_family']:<10} {best.get('label','—')}")
print("=" * 65)