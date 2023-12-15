"""
Sample client for the v2 API of Pentest-Tools.com.
This client starts a Web Server Scan, queries the output and writes the report in a HTML and a PDF file.?
A valid API key is necessary for this program to work.?

This client contains sample requests for most API methods

API Reference: https://pentest-tools.com/docs/api/v2

Python 3.9+ is assumed here
"""

import json
import sys
import time
import traceback
import urllib

import requests

API_KEY = "----------------------------------------"  #    <-- Place your API key here
API_URL = "https://pentest-tools.com/api/v2/"
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}


def init():
    global HEADERS
    HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}


class Tool:
    """Map the tool_id that the API knows to the tool name"""

    SUBDOMAIN_FINDER = 20
    TCP_PORT_SCANNER = 70
    UDP_PORT_SCANNER = 80
    URL_FUZZER = 90
    FIND_VHOSTS = 160
    WEBSITE_SCANNER = 170
    SHARE_POINT_SCANNER = 260
    WORDPRESS_SCANNER = 270
    DRUPAL_SCANNER = 280
    WEBSITE_RECON = 310
    NETWORK_SCANNER = 350
    DOMAIN_FINDER = 390
    PASSWORD_AUDITOR = 400
    SSL_SCANNER = 450
    SNIPER = 490
    CLOUD_SCANNER = 520


"""Scans

Two common ways to start a scan is by using either `target` or `target_id`.

`target` needs to be a simple URL, like "https://example.org". `target_id` is an
integer you can get from the `get_targets` method.

For both, you need:
- tool_id: ID of the tool you want to use
- tool_params: Options for the tool
- target or target_id: The target you want to scan, depending on the chosen method
"""


def start_scan(target, tool_id, tool_params, api_url=API_URL, headers=HEADERS):
    """Start a scan using the given target name"""
    data = {"tool_id": tool_id, "target_name": target, "tool_params": tool_params}
    return requests.post(api_url + "scans/", headers=headers, json=data)


def start_scan_by_targetid(target_id, tool_id, tool_params, api_url=API_URL, headers=HEADERS):
    """Start a scan using the given target_id"""
    data = {"tool_id": tool_id, "target_id": target_id, "tool_params": tool_params}
    return requests.post(api_url + "scans/", headers=headers, json=data)


"""Interacting with scans

After you started a scan, through either method, you may want to interact with it. These are the most commonly
used methods for interacting with scans after they have been started.

A scan is identified by a `scan_id`, which can be obtained from running `GET $API/scans`,
or `get_scans` from this client.

You can check the status of a scan using the `get_scan_status` function.

You can get the JSON output of a scan by calling `get_output` with a suitable `scan_id`.
The previous feature of getting output in a chosen format has moved to the `start_scan` function, through an URL callback. TODO: example

You may want to stop a running scan, which you can do with `stop_scan`.
Should you want to delete a scan entirely, tou can use the `delete_scan` function.

"""


def get_scans(workspace_id=None, target_id=None, api_url=API_URL, headers=HEADERS):
    """Get a list of scans

    Specific parameters:
    - workspace_id  -- when set, only the scans from this workspace will be returned
                        (you can get a list of workspaces by using the `get_workspaces` operation)
    - target_id     -- when set, only the scans run on this target will be returned
                        (use `get_targets` for the target list)
    """
    data = {}
    if workspace_id is not None:
        data["workspace_id"] = workspace_id
    if target_id is not None:
        data["target_id"] = target_id
    params = "?" + urllib.parse.urlencode(data)
    return requests.get(api_url + f"scans{params}", headers=headers)


def get_scan_status(scan_id, api_url=API_URL, headers=HEADERS):
    """Get the status of a scan"""
    return requests.get(api_url + f"scans/{scan_id}", headers=headers)


def get_output(scan_id, api_url=API_URL, headers=HEADERS):
    """Get the output of a scan"""
    return requests.get(api_url + f"scans/{scan_id}/output", headers=headers)


def stop_scan(scan_id, api_url=API_URL, headers=HEADERS):
    """Stop a running scan"""
    return requests.post(api_url + f"/scans/{scan_id}/stop", headers=headers)


def delete_scan(scan_id, api_url=API_URL, headers=HEADERS):
    """Delete a scan"""
    return requests.delete(api_url + f"/scans/{scan_id}", headers=headers)


"""Targets

Although you can interact with targets manually, by inputting the URL everytime, Pentest-Tools offers facilities of working with targets.

The simples workflow involves three functions: Add a target with `add_target`, get all targets with `get_targets` and get a single target with
`get_target_by_id`.

Deleting and updating targets remain, for now, an operation you can only do throught the site.
"""


def add_target(name, description="", workspace_id=None, api_url=API_URL, headers=HEADERS):
    """Add a new target

    Specific parameters:
    - name          -- the name of the target (must be a hostname, IP address or URL)
    - description   -- a short description of the target (optional)
    - workspace_id  -- the specific workspace in which to add this target (optional)
    """
    data = {"name": name}
    if len(description) > 0:
        data["description"] = description
    if workspace_id is not None:
        data["workspace_id"] = workspace_id

    return requests.post(api_url + "targets", headers=headers, json=data)


def get_targets(api_url=API_URL, headers=HEADERS):
    """Get a list of targets"""
    return requests.get(api_url + "targets", headers=headers)


def get_target_by_id(target_id, api_url=API_URL, headers=HEADERS):
    """Update the description of a target

    Specific parameters:
    - target_id     -- the ID of the updated target
    """
    return requests.get(api_url + f"targets/{target_id}", headers=headers)


if __name__ == "__main__":
    # `tool_params` is specific to the tool
    # Here we do a light scan with the Web Server Scanner
    tool_id = Tool.WEBSITE_SCANNER
    tool_params = {"scan_type": "light"}
    target = "http://demo.pentest-tools.com/webapp/"

    # Start the scan
    res = start_scan(target, tool_id, tool_params)
    try:
        res_json = res.json()
    except requests.exceptions.JSONDecodeError:
        print(traceback.format_exc())
        print(res.text)
        sys.exit(1)

    # Get the new `scan_id`
    if "data" in res_json and "created_id" in res_json["data"]:
        scan_id = res_json["data"]["created_id"]
        print("Started scan %i" % scan_id)
    else:
        print("Scan could not start")
        print(f"Status: {res_json['status']}, message: {res_json['message']}")
        sys.exit(1)

    # Poll periodically to check if the scan is finished
    while True:
        time.sleep(2)

        # Get the status of our scan
        status = get_scan_status(scan_id)
        status_name = status.json()["data"]["status_name"]

        if status_name == "finished":
            print("Scan status: %s" % res_json["data"])
            # Get the HTML report and write it to a file
            print("Getting JSON report")
            res = get_output(scan_id)
            output_json = res.json()

            with open("report.json", "w") as file:
                json.dump(output_json, file)

            print("JSON report written to file")
            break
