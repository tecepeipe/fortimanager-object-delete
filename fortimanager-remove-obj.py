# enable webservice on Network Interface
# enable http access and disable https redirection
# create an api user and allow JSON API access as Read Write
# update IP / policy package variables 
# Add dependencies with python -m pip install requests 
# List only, run as: python remove-c.py server2
# To Remove add --remove
# For multiple objects use paramater --file with a .txt file with object names (one per line)


import requests
import argparse
import json
import os

# 🔧 Configuration
FMG_HOST = "http://192.168.1.250"    # Replace with your FortiManager IP or hostname
USERNAME = "admin"                   # Replace with your FortiManager username
PASSWORD = "password1"               # Replace with your FortiManager password
ADOM = "root"                        # Replace with your ADOM name if different
POLICY_PACKAGE = "default"           # Replace with your policy package name

requests.packages.urllib3.disable_warnings()

def login():
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "exec",
        "params": [{
            "url": "/sys/login/user",
            "data": {"user": USERNAME, "passwd": PASSWORD}
        }],
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    if "session" in result:
        return result["session"]
    elif "result" in result and "session" in result["result"][0]:
        return result["result"][0]["session"]
    else:
        print("❌ Login failed. Response:")
        print(json.dumps(result, indent=2))
        raise Exception("Could not retrieve session token.")

def logout(session):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "exec",
        "params": [{"url": "/sys/logout"}],
        "session": session,
        "id": 1
    }
    requests.post(url, json=payload, verify=False)

def object_exists(session, obj_name):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/address/{obj_name}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    return "result" in result and result["result"][0]["status"]["code"] == 0

def get_firewall_policies(session):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{POLICY_PACKAGE}/firewall/policy"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    try:
        return result["result"][0]["data"]
    except (KeyError, IndexError):
        print("❌ Failed to retrieve firewall policies. Full response:")
        print(json.dumps(result, indent=2))
        raise Exception("Could not find 'data' in firewall policy response.")

def update_policy(session, policy_id, field, new_list):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "update",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{POLICY_PACKAGE}/firewall/policy/{policy_id}",
            "data": {field: new_list}
        }],
        "session": session,
        "id": 1
    }
    requests.post(url, json=payload, verify=False)
    print(f"✅ Updated policy {policy_id}: {field} → {new_list}")

def delete_policy(session, policy_id):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "delete",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{POLICY_PACKAGE}/firewall/policy/{policy_id}"
        }],
        "session": session,
        "id": 1
    }
    requests.post(url, json=payload, verify=False)
    print(f"🗑️ Deleted policy {policy_id}")

def delete_address_object(session, obj_name):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "delete",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/address/{obj_name}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    if "result" in result and result["result"][0]["status"]["code"] == 0:
        print(f"🧹 Deleted address object '{obj_name}'")
    else:
        print(f"⚠️ Failed to delete object '{obj_name}'. Response:")
        print(json.dumps(result, indent=2))

def process_object(session, obj_name, remove=False):
    if not object_exists(session, obj_name):
        print(f"❌ Object '{obj_name}' not found in FortiManager.")
        return

    policies = get_firewall_policies(session)
    used = False

    for policy in policies:
        pid = policy.get("policyid")
        name = policy.get("name", "Unnamed")
        src = policy.get("srcaddr", [])
        dst = policy.get("dstaddr", [])

        used_in_src = obj_name in src
        used_in_dst = obj_name in dst

        if used_in_src or used_in_dst:
            used = True
            print(f"\n🔍 Policy ID {pid} ({name}) uses object '{obj_name}'")
            if not remove:
                continue

            if used_in_src and len(src) == 1:
                delete_policy(session, pid)
            elif used_in_src:
                src.remove(obj_name)
                update_policy(session, pid, "srcaddr", src)

            if used_in_dst and len(dst) == 1:
                delete_policy(session, pid)
            elif used_in_dst:
                dst.remove(obj_name)
                update_policy(session, pid, "dstaddr", dst)

    if not used:
        print(f"ℹ️ Object '{obj_name}' not used in any policy.")

    if remove:
        delete_address_object(session, obj_name)

def load_objects_from_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="FortiManager Firewall Rule Inspector")
    parser.add_argument("objects", nargs="*", help="IP or object names to search")
    parser.add_argument("--file", help="Path to .txt file with object names (one per line)")
    parser.add_argument("--remove", action="store_true", help="Remove object or rule if exclusively used")
    args = parser.parse_args()

    all_objects = args.objects
    if args.file:
        try:
            file_objects = load_objects_from_file(args.file)
            all_objects.extend(file_objects)
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return

    if not all_objects:
        print("⚠️ No objects provided. Use positional args or --file.")
        return

    session = login()
    try:
        for obj in all_objects:
            process_object(session, obj, remove=args.remove)
    finally:
        logout(session)

if __name__ == "__main__":
    main()