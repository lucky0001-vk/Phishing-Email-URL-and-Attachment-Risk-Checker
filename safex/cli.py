import sys
import os
import argparse
import json

# Ensure UTF-8 output on Windows consoles to prevent cp1252 encoding errors
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from safex.core.analyzer import analyze_email
from safex.core.test_samples import get_test_samples

console = Console(highlight=False)


def print_banner():
    banner = Text()
    banner.append("🛡️  SAFEX ", style="bold cyan")
    banner.append("— Static Phishing & Attachment Decision-Support Engine\n", style="bold white")
    banner.append("   Offline static threat triage • In-memory parsing • No cloud leaks • Air-gapped safe", style="dim italic")
    console.print(Panel(banner, border_style="cyan", box=box.ROUNDED))


def display_results(result, title="Analysis Report"):
    # Determine color scheme based on risk rating
    color_map = {
        "LOW": ("green", "✅ LOW RISK / LIKELY BENIGN"),
        "MEDIUM": ("yellow", "⚠️ MEDIUM RISK / SUSPICIOUS"),
        "HIGH": ("red", "🚨 HIGH PHISHING RISK"),
        "CRITICAL": ("bold white on red", "⛔ CRITICAL THREAT DETECTED"),
    }
    style_color, verdict_label = color_map.get(result.risk_rating, ("white", result.risk_rating))

    # Overall Score Panel
    score_text = Text()
    score_text.append(f"\n   OVERALL RISK SCORE: ", style="bold white")
    score_text.append(f"{result.overall_score}/100   ", style=f"bold {style_color}")
    score_text.append(f"[{verdict_label}]\n\n", style=f"{style_color}")
    score_text.append(f"   Summary: {result.summary}\n", style="white")
    score_text.append(f"   Timestamp: {result.analysis_timestamp}\n", style="dim")

    console.print(Panel(score_text, title=f"[bold]Verdict: {title}[/bold]", border_style=style_color.split()[-1], box=box.HEAVY))

    # Score Breakdown Table
    breakdown_table = Table(title="📊 Risk Component Breakdown", box=box.SIMPLE_HEAVY)
    breakdown_table.add_column("Vector", style="cyan")
    breakdown_table.add_column("Score", justify="right", style="bold")
    breakdown_table.add_column("Status / Highlights", style="white")

    h_score = result.score_breakdown["header_score"]
    b_score = result.score_breakdown["body_url_score"]
    a_score = result.score_breakdown["attachment_score"]

    breakdown_table.add_row(
        "Headers & Sender Auth",
        f"{h_score} pts",
        f"SPF: {result.header_analysis.spf_status or 'N/A'} | DKIM: {result.header_analysis.dkim_status or 'N/A'} | Spoofing: {'YES' if result.header_analysis.display_name_spoof else 'No'}"
    )
    breakdown_table.add_row(
        "Body Rhetoric & URLs",
        f"{b_score} pts",
        f"Links: {len(result.body_analysis.links)} | Urgency phrases: {len(result.body_analysis.urgency_phrases_detected)}"
    )
    breakdown_table.add_row(
        "Static Attachment Inspection",
        f"{a_score} pts",
        f"Total attachments: {len(result.attachments)} | Mismatches: {sum(1 for a in result.attachments if a.type_mismatch)}"
    )
    console.print(breakdown_table)

    # Contributing Warning Signals Table
    if result.all_signals:
        sig_table = Table(title="🔍 Contributing Warning Signs & Evidence", box=box.ROUNDED)
        sig_table.add_column("Category", style="cyan", width=12)
        sig_table.add_column("Rule Triggered", style="bold yellow", width=32)
        sig_table.add_column("Severity", width=10)
        sig_table.add_column("Impact", justify="right", width=8)
        sig_table.add_column("Explanation & Evidence", style="dim white")

        sev_colors = {
            "info": "blue",
            "low": "cyan",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }

        for sig in result.all_signals:
            sc = sev_colors.get(sig.severity.lower(), "white")
            expl = f"{sig.description}"
            if sig.evidence:
                expl += f"\n[bold yellow]Evidence:[/bold yellow] [dim]{sig.evidence}[/dim]"

            sig_table.add_row(
                sig.category.upper(),
                sig.name,
                Text(sig.severity.upper(), style=sc),
                f"+{sig.score_impact}",
                expl
            )
        console.print(sig_table)
    else:
        console.print(Panel("[green]✓ No threat indicators or anomalous signals detected.[/green]", box=box.ROUNDED))

    # Attachment Inventory Table (if any)
    if result.attachments:
        att_table = Table(title="📎 Static Attachment Inventory", box=box.ROUNDED)
        att_table.add_column("Filename", style="bold white")
        att_table.add_column("Declared MIME", style="dim")
        att_table.add_column("Detected Magic Signature", style="cyan")
        att_table.add_column("Size", style="magenta")
        att_table.add_column("SHA-256 (First 16)", style="dim")
        att_table.add_column("Risk Verdict", style="bold")

        for att in result.attachments:
            att_color = "green" if att.risk_level == "CLEAN" else "red" if att.risk_level in ["MALICIOUS", "CRITICAL"] else "yellow"
            att_table.add_row(
                att.filename,
                att.declared_mime_type,
                att.magic_signature,
                att.size_human,
                att.sha256[:16] + "..." if att.sha256 else "N/A",
                Text(att.risk_level, style=att_color)
            )
        console.print(att_table)

    # Safe Action Guidance Panel
    guidance = result.safe_guidance
    guidance_text = Text()
    guidance_text.append(f"\n{guidance.headline}\n", style="bold cyan")

    guidance_text.append("\nRecommended Verification Steps:\n", style="bold white")
    for step in guidance.verification_steps:
        guidance_text.append(f"  • {step}\n", style="white")

    if guidance.recommendations:
        guidance_text.append("\nSpecific Recommendations:\n", style="bold green")
        for rec in guidance.recommendations:
            guidance_text.append(f"  ✓ {rec}\n", style="green")

    if guidance.things_to_avoid:
        guidance_text.append("\nStrictly Avoid:\n", style="bold red")
        for avoid in guidance.things_to_avoid:
            guidance_text.append(f"  ✗ {avoid}\n", style="red")

    guidance_text.append(f"\n[dim italic]Disclaimer: {result.disclaimer}[/dim italic]\n")
    console.print(Panel(guidance_text, title="🛡️ Safe Action Protocol & Guidance", border_style="cyan", box=box.ROUNDED))


def main():
    parser = argparse.ArgumentParser(description="SafeX Static Email & Attachment Phishing Analyzer")
    parser.add_argument("file", nargs="?", help="Path to .eml or text email sample file")
    parser.add_argument("--sample", type=int, choices=range(1, 10), help="Run built-in test sample (1 to 9)")
    parser.add_argument("--json", action="store_true", help="Output results in raw JSON format")
    parser.add_argument("--list-samples", action="store_true", help="List all 9 available test scenarios")

    args = parser.parse_args()

    if args.list_samples:
        samples = get_test_samples()
        console.print("\n[bold cyan]Available SafeX Test Scenarios:[/bold cyan]\n")
        for key, s in samples.items():
            console.print(f"  [bold yellow]{s['id']}. {s['title']}[/bold yellow]")
            console.print(f"     [dim]{s['description']}[/dim]\n")
        return

    if args.sample:
        samples = get_test_samples()
        key = list(samples.keys())[args.sample - 1]
        sample = samples[key]
        result = analyze_email(sample["email_text"], sample["attachments"])

        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            print_banner()
            display_results(result, title=f"Sample #{args.sample}: {sample['title']}")
        return

    if args.file:
        if not os.path.exists(args.file):
            console.print(f"[bold red]Error:[/bold red] File '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "rb") as f:
            raw_bytes = f.read()
        result = analyze_email(raw_bytes)
        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            print_banner()
            display_results(result, title=f"File: {os.path.basename(args.file)}")
        return

    # Check if input is piped into stdin
    if not sys.stdin.isatty():
        content = sys.stdin.read()
        result = analyze_email(content)
        if args.json:
            print(result.model_dump_json(indent=2))
        else:
            print_banner()
            display_results(result, title="Standard Input Stream")
        return

    # No input provided: show help and interactive prompt
    print_banner()
    console.print("\n[yellow]No email file provided. Try running with a built-in scenario:[/yellow]")
    console.print("  [cyan]python safex_cli.py --sample 1[/cyan] (Legitimate urgent notice - False positive check)")
    console.print("  [cyan]python safex_cli.py --sample 2[/cyan] (Disguised MZ executable in .pdf)")
    console.print("  [cyan]python safex_cli.py --sample 3[/cyan] (Macro-enabled weaponized Word doc)")
    console.print("  [cyan]python safex_cli.py --sample 4[/cyan] (Brand phishing & link mismatch)")
    console.print("  [cyan]python safex_cli.py --sample 5[/cyan] (Password-protected ZIP with body password)")
    console.print("  [cyan]python safex_cli.py --list-samples[/cyan] (List all 9 scenarios)")
    console.print("  [cyan]python -m safex.web.app[/cyan] (Launch the interactive Web UI)\n")


if __name__ == "__main__":
    main()
