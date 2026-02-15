#!/usr/bin/env python
"""Debug script for XSS scanner"""
import sys
import asyncio
import json

sys.path.insert(0, "d:/vuln_Scanner/model")
from xss_scanner import XSSDetectionOrchestrator, XSSExecutionPlan


async def test():
    o = XSSDetectionOrchestrator()
    target = "http://testphp.vulnweb.com/search.php?test=query"

    plan_data = o.generate_execution_plan(target)
    print(f'Target: {plan_data["target"]}')
    print(f'Total plans: {plan_data["total_plans"]}')

    for p in plan_data["execution_plans"]:
        print(f'  - {p["tool"]} ({p["scan_type"]}): {p["command"][0]}')

    # Get first plan and convert to XSSExecutionPlan
    first_plan_dict = plan_data["execution_plans"][0]
    first_plan = XSSExecutionPlan(**first_plan_dict)

    print("\nRunning first tool (dalfox reflected)...")
    result = await o.execute_tool(first_plan, plan_data["target"])
    print(f"Result: success={result.success}, findings_count={result.findings_count}")

    if result.error:
        print(f"Error: {result.error}")

    if result.raw_output:
        print(f"Raw output (first 1000 chars): {result.raw_output[:1000]}")

    if result.findings:
        print(f"\nFindings ({len(result.findings)} total):")
        for f in result.findings[:5]:
            print(f'  - {f.get("severity", "?")} - {f.get("type", "?")}')


if __name__ == "__main__":
    asyncio.run(test())
