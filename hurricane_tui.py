#!/usr/bin/env python3
"""
HURRICANE Control Center - Rich Interactive TUI
A user-friendly interface with zero command memorization required
"""

import os
import sys
import subprocess
import signal
import webbrowser
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich.align import Align
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich.live import Live
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.style import Style
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Installing rich library...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.style import Style
    from rich import box

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
WEBUI_URL = "http://127.0.0.1:8643"
DAEMON_URL = "http://127.0.0.1:8642"

console = Console()


def get_banner():
    """Generate the HURRICANE banner"""
    banner = """
 ██╗  ██╗██╗   ██╗██████╗ ██████╗ ██╗ ██████╗ █████╗ ███╗   ██╗███████╗
 ██║  ██║██║   ██║██╔══██╗██╔══██╗██║██╔════╝██╔══██╗████╗  ██║██╔════╝
 ███████║██║   ██║██████╔╝██████╔╝██║██║     ███████║██╔██╗ ██║█████╗
 ██╔══██║██║   ██║██╔══██╗██╔══██╗██║██║     ██╔══██║██║╚██╗██║██╔══╝
 ██║  ██║╚██████╔╝██║  ██║██║  ██║██║╚██████╗██║  ██║██║ ╚████║███████╗
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
    """
    return banner


def check_service_status():
    """Check if services are running"""
    status = {"daemon": False, "api": False, "webui": False}

    try:
        import urllib.request
        # Check daemon
        try:
            urllib.request.urlopen(f"{DAEMON_URL}/health", timeout=2)
            status["daemon"] = True
        except:
            pass

        # Check API/WebUI
        try:
            urllib.request.urlopen(f"{WEBUI_URL}/routing/status", timeout=2)
            status["api"] = True
            status["webui"] = True
        except:
            pass
    except:
        pass

    return status


def create_status_panel():
    """Create a status panel showing service states"""
    status = check_service_status()

    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    table.add_column("Service", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("URL", style="dim")

    daemon_status = "[green]● ONLINE[/green]" if status["daemon"] else "[red]○ OFFLINE[/red]"
    api_status = "[green]● ONLINE[/green]" if status["api"] else "[red]○ OFFLINE[/red]"
    webui_status = "[green]● ONLINE[/green]" if status["webui"] else "[red]○ OFFLINE[/red]"

    table.add_row("v6-gatewayd Daemon", daemon_status, DAEMON_URL)
    table.add_row("Comprehensive API", api_status, WEBUI_URL)
    table.add_row("WebUI Interface", webui_status, WEBUI_URL)

    return Panel(table, title="[bold cyan]Service Status[/bold cyan]", border_style="cyan")


def create_main_menu():
    """Create the main menu panel"""
    menu = Table(box=None, show_header=False, padding=(0, 2))
    menu.add_column("Key", style="bold yellow", width=6)
    menu.add_column("Action", style="white")
    menu.add_column("Description", style="dim")

    menu.add_row("", "", "")
    menu.add_row("[1]", "Start Services", "Launch daemon, API, and WebUI")
    menu.add_row("[2]", "Stop Services", "Shutdown all running services")
    menu.add_row("[3]", "Restart Services", "Stop and restart everything")
    menu.add_row("[4]", "Open WebUI", "Launch WebUI in browser")
    menu.add_row("", "", "")
    menu.add_row("[5]", "Port Scanner", "Run FASTPORT scanner TUI")
    menu.add_row("[6]", "CVE Scanner", "Run vulnerability scanner")
    menu.add_row("[7]", "View Logs", "Show service logs")
    menu.add_row("", "", "")
    menu.add_row("[8]", "Routing Config", "Configure IPv6/IPv9 routing")
    menu.add_row("[9]", "Split Tunneling", "Configure split tunnel rules")
    menu.add_row("", "", "")
    menu.add_row("[0]", "Exit", "Quit HURRICANE Control Center")

    return Panel(menu, title="[bold green]Main Menu[/bold green]", border_style="green")


def create_routing_menu():
    """Create routing configuration submenu"""
    menu = Table(box=None, show_header=False, padding=(0, 2))
    menu.add_column("Key", style="bold yellow", width=6)
    menu.add_column("Action", style="white")

    menu.add_row("[1]", "IPv6 Mode (Hurricane Electric)")
    menu.add_row("[2]", "IPv9 Mode (China Decimal Network)")
    menu.add_row("[3]", "Dual Stack Mode")
    menu.add_row("[4]", "Show Current Mode")
    menu.add_row("[0]", "Back to Main Menu")

    return Panel(menu, title="[bold magenta]Routing Configuration[/bold magenta]", border_style="magenta")


def run_command(cmd, capture=False):
    """Run a shell command"""
    try:
        if capture:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=SCRIPT_DIR)
            return result.stdout + result.stderr
        else:
            subprocess.run(cmd, shell=True, cwd=SCRIPT_DIR)
            return None
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return None


def start_services():
    """Start all HURRICANE services and open WebUI"""
    console.print("\n[cyan]Starting HURRICANE services...[/cyan]\n")
    run_command("./hurricane start")

    # Wait a moment for services to start
    time.sleep(2)

    # Check if services are up and open WebUI
    status = check_service_status()
    if status["webui"]:
        console.print("\n[green]Services started successfully![/green]")
        if Confirm.ask("\n[yellow]Open WebUI in browser?[/yellow]", default=True):
            open_webui()
    else:
        console.print("\n[yellow]Services may still be starting. Try opening WebUI in a moment.[/yellow]")


def stop_services():
    """Stop all HURRICANE services"""
    console.print("\n[cyan]Stopping HURRICANE services...[/cyan]\n")
    run_command("./hurricane stop")


def restart_services():
    """Restart all HURRICANE services"""
    console.print("\n[cyan]Restarting HURRICANE services...[/cyan]\n")
    run_command("./hurricane restart")

    time.sleep(2)
    status = check_service_status()
    if status["webui"]:
        if Confirm.ask("\n[yellow]Open WebUI in browser?[/yellow]", default=True):
            open_webui()


def open_webui():
    """Open the WebUI in the default browser"""
    status = check_service_status()
    if not status["webui"]:
        console.print("[yellow]WebUI is not running. Start services first.[/yellow]")
        if Confirm.ask("Start services now?", default=True):
            start_services()
        return

    console.print(f"\n[green]Opening WebUI at {WEBUI_URL}[/green]")
    try:
        webbrowser.open(WEBUI_URL)
    except Exception as e:
        console.print(f"[yellow]Could not open browser automatically.[/yellow]")
        console.print(f"[cyan]Please open manually: {WEBUI_URL}[/cyan]")


def run_port_scanner():
    """Launch the FastPort Scanner TUI"""
    scanner_paths = [
        SCRIPT_DIR / "fastport" / "fastport" / "scanner_pro_tui.py",
        SCRIPT_DIR / "fastport" / "fastport" / "scanner_tui.py",
    ]

    for path in scanner_paths:
        if path.exists():
            console.print(f"\n[cyan]Launching FastPort Scanner...[/cyan]\n")
            target = Prompt.ask("[yellow]Enter target IP/hostname[/yellow]", default="127.0.0.1")
            ports = Prompt.ask("[yellow]Enter ports (e.g., 1-1000, 80,443)[/yellow]", default="1-1000")
            subprocess.run([sys.executable, str(path), target, "-p", ports])
            return

    console.print("[red]Scanner TUI not found.[/red]")


def run_cve_scanner():
    """Launch the CVE Scanner TUI"""
    scanner_path = SCRIPT_DIR / "fastport" / "fastport" / "cve_scanner_tui.py"

    if scanner_path.exists():
        console.print(f"\n[cyan]Launching CVE Scanner...[/cyan]\n")
        target = Prompt.ask("[yellow]Enter target IP/hostname[/yellow]", default="127.0.0.1")
        subprocess.run([sys.executable, str(scanner_path), target])
    else:
        console.print("[red]CVE Scanner TUI not found.[/red]")


def view_logs():
    """View service logs submenu"""
    console.clear()

    menu = Table(box=None, show_header=False, padding=(0, 2))
    menu.add_column("Key", style="bold yellow", width=6)
    menu.add_column("Action", style="white")

    menu.add_row("[1]", "Daemon Logs")
    menu.add_row("[2]", "API Logs")
    menu.add_row("[3]", "All Logs")
    menu.add_row("[0]", "Back")

    console.print(Panel(menu, title="[bold cyan]View Logs[/bold cyan]", border_style="cyan"))

    choice = Prompt.ask("\n[yellow]Select option[/yellow]", choices=["0", "1", "2", "3"], default="3")

    if choice == "1":
        run_command("./hurricane logs daemon")
    elif choice == "2":
        run_command("./hurricane logs api")
    elif choice == "3":
        run_command("./hurricane logs all")


def configure_routing():
    """Routing configuration submenu"""
    while True:
        console.clear()
        print_header()
        console.print(create_routing_menu())

        choice = Prompt.ask("\n[yellow]Select routing mode[/yellow]", choices=["0", "1", "2", "3", "4"], default="0")

        if choice == "0":
            break
        elif choice == "1":
            set_routing_mode("ipv6")
        elif choice == "2":
            set_routing_mode("ipv9")
        elif choice == "3":
            set_routing_mode("dual")
        elif choice == "4":
            show_routing_status()

        Prompt.ask("\n[dim]Press Enter to continue[/dim]")


def set_routing_mode(mode):
    """Set the routing mode via API"""
    try:
        import urllib.request
        import json

        data = json.dumps({"mode": mode}).encode('utf-8')
        req = urllib.request.Request(
            f"{WEBUI_URL}/routing/mode",
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        response = urllib.request.urlopen(req, timeout=5)
        result = json.loads(response.read().decode('utf-8'))
        console.print(f"[green]Routing mode set to: {mode.upper()}[/green]")
    except Exception as e:
        console.print(f"[red]Failed to set routing mode: {e}[/red]")
        console.print("[yellow]Make sure services are running.[/yellow]")


def show_routing_status():
    """Show current routing status"""
    try:
        import urllib.request
        import json

        response = urllib.request.urlopen(f"{WEBUI_URL}/routing/status", timeout=5)
        status = json.loads(response.read().decode('utf-8'))

        table = Table(title="Routing Status", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in status.items():
            table.add_row(str(key), str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to get routing status: {e}[/red]")


def configure_split_tunnel():
    """Split tunneling configuration"""
    console.clear()
    console.print(Panel(
        "[cyan]Split Tunneling Configuration[/cyan]\n\n"
        "Configure which traffic goes through which route.\n"
        "This feature is available in the WebUI for easier management.",
        title="Split Tunneling",
        border_style="magenta"
    ))

    if Confirm.ask("\n[yellow]Open WebUI to configure split tunneling?[/yellow]", default=True):
        open_webui()


def print_header():
    """Print the application header"""
    banner_text = Text(get_banner(), style="bold cyan")
    console.print(Align.center(banner_text))
    console.print(Align.center(Text("v6-gatewayd Control Center", style="bold white")))
    console.print(Align.center(Text("IPv6/IPv9 Dual-Stack Gateway Management", style="dim")))
    console.print()


def main_loop():
    """Main application loop"""
    while True:
        console.clear()
        print_header()

        # Show status and menu side by side if terminal is wide enough
        console.print(create_status_panel())
        console.print()
        console.print(create_main_menu())

        try:
            choice = Prompt.ask(
                "\n[bold yellow]Enter your choice[/bold yellow]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                default="4"
            )

            if choice == "0":
                console.print("\n[cyan]Goodbye![/cyan]\n")
                break
            elif choice == "1":
                start_services()
            elif choice == "2":
                stop_services()
            elif choice == "3":
                restart_services()
            elif choice == "4":
                open_webui()
            elif choice == "5":
                run_port_scanner()
            elif choice == "6":
                run_cve_scanner()
            elif choice == "7":
                view_logs()
            elif choice == "8":
                configure_routing()
            elif choice == "9":
                configure_split_tunnel()

            if choice not in ["0", "8"]:
                Prompt.ask("\n[dim]Press Enter to continue[/dim]")

        except KeyboardInterrupt:
            console.print("\n\n[cyan]Goodbye![/cyan]\n")
            break


def main():
    """Main entry point"""
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    # Check for command line arguments for quick actions
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            start_services()
            return
        elif cmd == "stop":
            stop_services()
            return
        elif cmd == "status":
            console.print(create_status_panel())
            return
        elif cmd == "webui":
            open_webui()
            return

    # Run interactive TUI
    main_loop()


if __name__ == "__main__":
    main()
