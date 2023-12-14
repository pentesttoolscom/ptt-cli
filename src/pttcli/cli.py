"""
The CLI module for PentestTools.com. It uses PTT API and formats output.
"""
import argparse
import functools
import html
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from . import banner
from . import api


ARGS = None
STARTED_SCANS = []
LAST_SCAN_OUTPUT = None
SUMMARY = None


def start_scan_instance(target, tool_id):
    """Starts a scan through the API.

    Returns a Scan object associated to the started scan.
    """
    tool_params = {
        "scan_type": "light",
    }
    res = api.start_scan(target, tool_id, tool_params)
    res_json = res.json()
    if "data" in res_json and "created_id" in res_json["data"]:
        scan_id = res_json["data"]["created_id"]
        scan = Scan(scan_id)
        STARTED_SCANS.append(scan)
        return scan

    return None


def stop_started_scans():
    """Stops all started scans."""
    for scan in STARTED_SCANS:
        api.stop_scan(scan.scan_id)


def resource_handler_wrapper(func):
    """Decorator used to catch all exceptions. Tries to write the scan results and stop the running
    scans."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        raised_exc = None
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as exc:
            raised_exc = exc
            print(
                "An HTTP error has occured. Stopping scans and writing output. \
                Press Ctrl+C to terminate forcefully.",
                file=sys.stderr,
            )
            write_result()
            stop_started_scans()
        except KeyboardInterrupt as exc:
            raised_exc = exc
            print(
                "A stop was requested. Stopping scans and writing output. \
                Press Ctrl+C again to terminate forcefully.",
                file=sys.stderr,
            )
            write_result()
            stop_started_scans()
        except Exception as exc:
            raised_exc = exc
            print(
                "An error has occured. Stopping scans and writing output. \
                Press Ctrl+C to terminate forcefully.",
                file=sys.stderr,
            )
            write_result()
            stop_started_scans()

        if ARGS.verbose:
            raise raised_exc

        return None

    return wrapper


RUNNING_ANIMATION = "|/-\\"
RUN_IDX = 0


def print_runtime_status(progress, start_time, duration, total_tests, finished_tests, del_prev=False):
    """Prints the status of a current scan. Shows a bar that fills from 0% to 100% progress. Has
    rotating bar animation."""
    global RUN_IDX

    if del_prev:
        sys.stdout.write("\033\x5BF" * 7)
    progress_line = "*" * int((progress / 100) * 50) + "_" * int((1 - progress / 100) * 50)
    msg = f"Progress: {progress_line} {progress}%\n"
    msg += f"  Status: Running {RUNNING_ANIMATION[RUN_IDX]}\n"
    RUN_IDX = (RUN_IDX + 1) % len(RUNNING_ANIMATION)
    msg += f"  Start time: {start_time}\n"

    duration_measure_unit = "seconds"
    if duration == 1:
        duration_measure_unit = "second"
    elif duration >= 60:
        duration_measure_unit = "minutes"
        duration //= 60
        if duration == 1:
            duration_measure_unit = "minute"
    msg += f"  Duration: {duration} {duration_measure_unit}\n"

    msg += f"  Total tests: {total_tests}\n"
    msg += f"  Finished tests: {finished_tests}\n"

    print(msg)


def format_evidence(evidence, prefix=""):
    """Given a JSON of an evidence, generate a string containing the information.

    Args:
        evidence: The JSON obtained from the API.
        prefix: string to append to the beggining of each line.

    Returns the pretty formatted string.
    """
    if evidence["type"] == "text":
        if not evidence["data"]:
            return None
        return evidence["data"]

    msg = ""

    if evidence["type"] == "table":
        headers = evidence["data"]["headers"]
        rows = evidence["data"]["rows"]
        title_idx = -1
        if "CVE" in headers:
            title_idx = headers.index("CVE")
        elif "Description" in headers:
            title_idx = headers.index("Description")
        elif "Summary" in headers:
            title_idx = headers.index("Summary")

        msg = ""
        for row_idx, row in enumerate(rows, start=1):
            if title_idx == -1:
                msg += prefix + f"- Evidence {row_idx}:\n"
            else:
                msg += prefix + "- " + html.unescape(row[title_idx]) + ":\n"

            for idx, (header, data) in enumerate(zip(headers, row)):
                if idx == title_idx:
                    continue

                msg += prefix + "\t- " + header + ": " + html.unescape(data) + "\n"
            msg += "\n"

        return msg

    return None


def format_finding(index, name, description, risk, status, recommendation, evidence):
    """Given finding parameters, generate a string containing the information.

    Returns the pretty formatted string.
    """
    msg = f"[{index}] {name}\n"

    if risk == 0:
        return msg

    msg += f"\t- Status: {status.capitalize()}\n"

    risk_to_severity = ["Info", "Low", "Medium", "High"]
    severity = risk_to_severity[risk]
    msg += f"\t- Risk Level: {risk} ({severity})\n\n"

    msg += "\tVulnerability Details:\n"
    evidence_str = format_evidence(evidence, prefix="\t")
    if evidence_str:
        msg += evidence_str + "\n"

    msg += f"\t- Description: {description}\n"
    if recommendation:
        msg += f"\t- Recommendation: {recommendation}\n"

    msg += "\n"

    return msg


def print_report(outfile):
    """Prints a the findings of a scan to the given output file. The findings are taken from a JSON
    that was requested previously.

    Args:
        outfile: File to print to. It can also be sys.stdout.
    """
    if LAST_SCAN_OUTPUT is None:
        return

    data = LAST_SCAN_OUTPUT["data"]
    if data["output_type"] != "finding_list":
        return
    findings = data["output_data"]["findings"]

    title = "+" + "-" * 58 + "+\n"
    title += "|" + "Vulnerability Scan Report".center(58) + "|\n"
    title += "+" + "-" * 58 + "+\n\n"
    print(title, file=outfile)

    findings.sort(key=lambda x: -x["risk_level"])

    for index, finding in enumerate(findings, start=1):
        msg = format_finding(
            index,
            finding["name"],
            finding["vuln_description"],
            finding["risk_level"],
            finding["status"],
            finding["recommendation"],
            finding["vuln_evidence"],
        )
        print(msg, file=outfile)


def print_summary(target, outfile):
    """Prints a summary table about a finished scan. The summary is a JSON file that was
    requested previously from the API."""
    if SUMMARY is None:
        return

    high_cnt = SUMMARY["data"]["result_summary"]["high"]
    medium_cnt = SUMMARY["data"]["result_summary"]["medium"]
    low_cnt = SUMMARY["data"]["result_summary"]["low"]
    info_cnt = SUMMARY["data"]["result_summary"]["info"]
    start_time = SUMMARY["data"]["start_time"]
    end_time = SUMMARY["data"]["end_time"]

    sq_width = 50
    msg = "+" + " TEST SUMMARY ".center(sq_width - 2, "-") + "+\n"
    msg += "|" + " " * (sq_width - 2) + "|\n"
    msg += f"|  URL: {target}".ljust(sq_width - 1) + "|\n"
    msg += f"|  High Risk Findings: {high_cnt}".ljust(sq_width - 1) + "|\n"
    msg += f"|  Medium Risk Findings: {medium_cnt}".ljust(sq_width - 1) + "|\n"
    msg += f"|  Low Risk Findings: {low_cnt}".ljust(sq_width - 1) + "|\n"
    msg += f"|  Info Risk Findings: {info_cnt}".ljust(sq_width - 1) + "|\n"
    msg += f"|  Start time: {start_time}".ljust(sq_width - 1) + "|\n"
    msg += f"|  End time: {end_time}".ljust(sq_width - 1) + "|\n"
    msg += "|" + " " * (sq_width - 2) + "|\n"
    msg += "+" + "-" * (sq_width - 2) + "+\n"

    print(msg, file=outfile)


class Scan:
    """Represents a started scan."""

    def __init__(self, scan_id):
        self.scan_id = scan_id

    def get_output(self):
        """Returns the result of the scan."""
        return api.get_output(self.scan_id).json()

    def get_scan_status(self):
        """Returns the status of the scan."""
        return api.get_scan_status(self.scan_id).json()


def write_result(target=None):
    """Writes the scan result at stdout or in a file."""
    if not ARGS:
        return

    if target is None:
        target = ARGS.target

    if ARGS.output:
        try:
            with open(ARGS.output, "w", encoding="utf8") as file:
                if ARGS.json:
                    file.write(json.dumps(LAST_SCAN_OUTPUT))
                else:
                    print_report(file)
                    print_summary(target, file)
        except OSError:
            print(f"Could not open/write file: {ARGS.output}", file=sys.stderr)
        else:
            print(f"Output written to: {ARGS.output}")
    else:
        if ARGS.json:
            print(LAST_SCAN_OUTPUT)
        else:
            print_report(sys.stdout)
            print_summary(target, sys.stdout)


def scan_loop(scan):
    """Renders a live status of the scan, while talking to the API.
    Stops when the scan status is finished. Handles the requests on a separate thread.
    """
    global LAST_SCAN_OUTPUT

    # The number of seconds to wait, until saving the scan output
    get_output_delta = 60
    sec_per_tick = 0.2
    pool = ThreadPoolExecutor(max_workers=1)
    task = None

    last_t_get_output = time.time()
    ret = scan.get_scan_status()
    data = ret["data"]
    scan_running = True
    del_prev = False
    while scan_running:
        time.sleep(sec_per_tick)

        if time.time() - last_t_get_output > get_output_delta:
            LAST_SCAN_OUTPUT = scan.get_output()
            last_t_get_output = time.time()

        if task is None:
            task = pool.submit(scan.get_scan_status)
        elif task.done():
            ret = task.result()
            data = ret["data"]
            task = None
        print_runtime_status(
            data["progress"],
            data["start_time"],
            data["duration"],
            data["num_tests"],
            data["num_finished_tests"],
            del_prev=del_prev,
        )
        del_prev = del_prev or True
        if data["status_name"] == "finished":
            scan_running = False


def parse_args():
    """Parses the command line arguments.

    Returns an ArgumentParser object.
    """
    parser = argparse.ArgumentParser(
        description="Command line utility for PentestTools.com",
        prog="ptt-cli",
    )
    parser.add_argument("target", help="The URL to scan.")
    parser.add_argument("--api", help="The API key. If not provided, obtain one automatically.")
    parser.add_argument("--timeout", help="Time to wait for the scan.", default=1440)  # 24 hours
    parser.add_argument(
        "-o",
        "--output",
        help="File to write the report. If specified, suppress the default report output and redirect to the path.",
    )
    parser.add_argument("--json", action="store_true", help="If set, output the report in json format.")
    parser.add_argument("-v", "--verbose", action="store_true", help="If set, print debug information.")

    return parser.parse_args()


@resource_handler_wrapper
def cli():
    """Entrypoint function for the CLI."""
    global ARGS
    global LAST_SCAN_OUTPUT
    global SUMMARY
    ARGS = parse_args()

    if ARGS.api:
        api.API_KEY = ARGS.api
    api.init()

    # Validate api key
    api_key_valid = False
    res = api.get_scan_status(0)
    if res.headers.get("content-type") == "application/json":
        data = res.json()
        if res.status_code == 404 and data["status"] == 404 and "not exist" in data["message"]:
            api_key_valid = True
        elif res.status_code == 200 and "id" in data["data"]:
            api_key_valid = True
    if not api_key_valid:
        print(f"The API {api.API_URL} didn't respont properly. Your API key might be invalid.", file=sys.stderr)
        sys.exit(1)

    print(banner.BANNER)
    print(f"Scanning target: {ARGS.target}\n")

    ws = start_scan_instance(ARGS.target, api.Tool.WEBSITE_SCANNER)
    if ws is None:
        return

    scan_loop(ws)
    LAST_SCAN_OUTPUT = ws.get_output()
    SUMMARY = ws.get_scan_status()
    target_info = api.get_target_by_id(SUMMARY["data"]["target_id"])
    target = target_info.json()["data"]["name"]
    write_result(target)

    return 0
