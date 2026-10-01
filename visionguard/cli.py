"""
VisionGuard Command Line Interface (CLI)
"""

import argparse
import json
import sys
from pathlib import Path

from visionguard.core.config import VisionGuardConfig
from visionguard.core.schemas import TrustPassport
from visionguard.engine import VisionGuardEngine
from visionguard.modules.governance.passport import verify_trust_passport
from visionguard.modules.governance.json_schema import export_all_schemas
from visionguard.modules.red_team.benchmark import RedTeamBenchmark


def main():
    parser = argparse.ArgumentParser(
        prog="visionguard",
        description="VisionGuard: Fully Offline Computer-Vision Assurance Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command 1: audit
    audit_parser = subparsers.add_parser("audit", help="Run lifecycle assurance audit")
    audit_parser.add_argument("--dataset", type=str, help="Path to training dataset (COCO/YOLO/ImageFolder)")
    audit_parser.add_argument("--model", type=str, help="Path to model file (ONNX or PyTorch)")
    audit_parser.add_argument("--output", type=str, default="runs", help="Output directory for reports and passport")
    audit_parser.add_argument("--embedder", type=str, default="mobilenet_v3", help="Embedder (mobilenet_v3, dinov3, siglip2, ensemble)")

    # Command 2: redteam
    rt_parser = subparsers.add_parser("redteam", help="Run Red-Team in a Box attack benchmark")
    rt_parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")

    # Command 3: verify-passport
    vp_parser = subparsers.add_parser("verify-passport", help="Cryptographically verify a Trust Passport")
    vp_parser.add_argument("passport_file", type=str, help="Path to trust_passport.json")

    # Command 4: export-schemas
    es_parser = subparsers.add_parser("export-schemas", help="Export JSON schemas for findings & passport")
    es_parser.add_argument("--output", type=str, default="schemas", help="Output directory for schemas")

    # Command 5: serve
    serve_parser = subparsers.add_parser("serve", help="Launch VisionGuard API & Web Interface")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind")

    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "audit":
        print("[*] Starting VisionGuard Lifecycle Assurance Audit...")
        cfg = VisionGuardConfig(output_dir=args.output)
        engine = VisionGuardEngine(config=cfg, embedder_name=args.embedder)
        
        results = engine.run_full_audit(
            dataset_path=args.dataset,
            model_or_path=args.model,
            generate_html_report=True
        )

        passport: TrustPassport = results["trust_passport"]
        print(f"\n=======================================================")
        print(f"TRUST PASSPORT: {passport.passport_id}")
        print(f"Overall Disposition: {passport.overall_disposition.value}")
        print(f"Confidence:          {passport.overall_confidence:.0%}")
        print(f"Total Findings:      {passport.findings_summary['total']}")
        print(f"Signature Verified:  VALID (Ed25519)")
        print(f"HTML Report:         {results.get('html_report_path')}")
        print(f"=======================================================\n")

    elif args.command == "redteam":
        print(f"[*] Running Red-Team in a Box Benchmark (Seed={args.seed})...")
        benchmark = RedTeamBenchmark(seed=args.seed)
        summary = benchmark.run_full_benchmark()
        print("\n-------------------------------------------------------------")
        print(f"Macro Precision: {summary.macro_precision:.1%}")
        print(f"Macro Recall:    {summary.macro_recall:.1%}")
        print(f"Macro F1-Score:  {summary.macro_f1:.1%}")
        print("-------------------------------------------------------------")
        for sc in summary.scenarios_evaluated:
            print(f"[{sc.attack_family.upper()}] {sc.attack_name:<28} | F1: {sc.f1_score:.2f} | P: {sc.precision:.2f} | R: {sc.recall:.2f}")
        print("-------------------------------------------------------------\n")

    elif args.command == "verify-passport":
        path = Path(args.passport_file)
        if not path.is_file():
            print(f"[!] Error: Passport file not found: {path}")
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        passport = TrustPassport(**data)
        valid, msg = verify_trust_passport(passport)
        if valid:
            print(f"[+] PASSPORT VERIFIED: {passport.passport_id}")
            print(f"    Signer Public Key: {passport.signer_public_key_hex}")
            print(f"    Overall Disposition: {passport.overall_disposition.value}")
            print(f"    Status: {msg}")
        else:
            print(f"[-] VERIFICATION FAILED: {msg}")
            sys.exit(1)

    elif args.command == "export-schemas":
        out = Path(args.output)
        schemas = export_all_schemas(out)
        print(f"[+] Exported {len(schemas)} JSON schemas to {out.resolve()}")

    elif args.command == "serve":
        import uvicorn
        from visionguard.api.app import app
        print(f"[*] Launching VisionGuard Web Server on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
