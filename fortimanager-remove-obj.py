
# enable webservice on Network Interface
# enable http access and disable https redirection
# create an api user and allow JSON API access as Read Write
# Add dependencies with python -m pip install requests 
# run with python list-rules.py object-name
# add --remove if you really want to delete
# For multiple objects use paramater --file with a .txt file with object names (one per line)


import requests
import argparse
import json
import os
import getpass

# 🔧 Global placeholders (filled interactively)
# for unattended mode, use these variables and comment first lines on main ()
FMG_HOST = ""
USERNAME = ""
PASSWORD = ""
ADOM = "root"

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

def list_policy_packages(session):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/pkg/adom/{ADOM}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    try:
        return [pkg["name"] for pkg in result["result"][0]["data"]]
    except Exception:
        print("❌ Failed to list policy packages.")
        return []

def get_firewall_policies(session, package):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{package}/firewall/policy"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    try:
        return result["result"][0]["data"]
    except Exception:
        return []

def update_policy(session, package, policy_id, field, new_list):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "update",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{package}/firewall/policy/{policy_id}",
            "data": {field: new_list}
        }],
        "session": session,
        "id": 1
    }
    requests.post(url, json=payload, verify=False)
    print(f"✅ Updated policy {policy_id}: {field} → {new_list}")

def delete_policy(session, package, policy_id):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "delete",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/pkg/{package}/firewall/policy/{policy_id}"
        }],
        "session": session,
        "id": 1
    }
    requests.post(url, json=payload, verify=False)
    print(f"🗑️ Deleted policy {policy_id}")

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

def get_object_type(session, name):
    # Check if it's an address object
    if object_exists(session, name):
        return "address"

    # Check if it's an address group
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{name}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()
    if "result" in result and result["result"][0]["status"]["code"] == 0:
        return "group"

    return None

def process_object(session, obj_name, remove=False):
    if not object_exists(session, obj_name):
        print(f"❌ Object '{obj_name}' not found in FortiManager.")
        return

    # 🔍 Show address group membership regardless of --remove
    groups = find_address_groups(session, obj_name)
    if groups:
        print(f"📚 Object '{obj_name}' is a member of address groups: {', '.join(groups)}")
        for group in groups:
            process_group(session, group, remove)
    else:
        print(f"📚 Object '{obj_name}' is NOT a member of any address group.")

    found_anywhere = False

    for package in list_policy_packages(session):
        policies = get_firewall_policies(session, package)
        used = False
        print(f"\n📦 Policy package: {package}")

        for policy in policies:
            pid = policy.get("policyid")
            name = policy.get("name", "Unnamed")
            src = policy.get("srcaddr", [])
            dst = policy.get("dstaddr", [])

            used_in_src = obj_name in src
            used_in_dst = obj_name in dst

            if used_in_src or used_in_dst:
                used = True
                found_anywhere = True
                print(f"🔍 Policy ID {pid} ({name}) uses object '{obj_name}'")
                if not remove:
                    continue

                if used_in_src and len(src) == 1:
                    delete_policy(session, package, pid)
                elif used_in_src:
                    src.remove(obj_name)
                    update_policy(session, package, pid, "srcaddr", src)

                if used_in_dst and len(dst) == 1:
                    delete_policy(session, package, pid)
                elif used_in_dst:
                    dst.remove(obj_name)
                    update_policy(session, package, pid, "dstaddr", dst)

        if not used:
            print(f"ℹ️ Object '{obj_name}' NOT used in any policy in package '{package}'.")

    if remove:
        remove_from_address_groups(session, obj_name)
        delete_address_object(session, obj_name)
        cleanup_empty_unused_groups(session)

def process_group(session, group_name, remove=False):
    print(f"\n📦 Processing address group: {group_name}")

    # Get group members
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()

    try:
        members = result["result"][0]["data"].get("member", [])
        print(f"📚 Members: {', '.join(members) if members else 'None'}")
    except Exception:
        print(f"⚠️ Failed to retrieve members for group '{group_name}'")
        return

    # Check usage in policies
    used_in = []
    for package in list_policy_packages(session):
        policies = get_firewall_policies(session, package)
        for policy in policies:
            pid = policy.get("policyid")
            name = policy.get("name", "Unnamed")
            src = policy.get("srcaddr", [])
            dst = policy.get("dstaddr", [])
            if group_name in src or group_name in dst:
                used_in.append((package, pid, name, src, dst))

    if used_in:
        print(f"🔍 Group '{group_name}' is used in:")
        for pkg, pid, pname, _, _ in used_in:
            print(f"   - Policy ID {pid} ({pname}) in package '{pkg}'")

        # 🛑 Do not update policies unless --remove AND group is empty
        if remove and not members:
            for pkg, pid, pname, src, dst in used_in:
                    print(f"⚙️ Updating policy {pid} ({pname}) in package '{pkg}'...")
                    if group_name in src and len(src) == 1:
                        delete_policy(session, pkg, pid)
                    elif group_name in src:
                        src.remove(group_name)
                        update_policy(session, pkg, pid, "srcaddr", src)

                    if group_name in dst and len(dst) == 1:
                        delete_policy(session, pkg, pid)
                    elif group_name in dst:
                        dst.remove(group_name)
                        update_policy(session, pkg, pid, "dstaddr", dst)
    else:
        print(f"ℹ️ Group '{group_name}' is NOT used in any policy.")

    # Final deletion logic
    if remove:
        if not members:
            # Group is empty, safe to delete
            delete_payload = {
                "method": "delete",
                "params": [{
                    "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
                }],
                "session": session,
                "id": 1
            }
            requests.post(f"{FMG_HOST}/jsonrpc", json=delete_payload, verify=False)
            print(f"🧹 Deleted empty address group '{group_name}'")
        elif not used_in:
            # Group is unused, safe to delete
            delete_payload = {
                "method": "delete",
                "params": [{
                    "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
                }],
                "session": session,
                "id": 1
            }
            requests.post(f"{FMG_HOST}/jsonrpc", json=delete_payload, verify=False)
            print(f"🧹 Deleted unused address group '{group_name}'")
        
def load_objects_from_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def find_address_groups(session, obj_name):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()

    groups = []
    try:
        for grp in result["result"][0]["data"]:
            members = grp.get("member", [])
            if obj_name in members:
                groups.append(grp["name"])
    except Exception:
        print("⚠️ Failed to parse address groups.")
    return groups

def check_and_cleanup_group_usage(session, group_name):
    # Check if group is empty
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()

    try:
        members = result["result"][0]["data"].get("member", [])
        if members:
            return  # Group is not empty, skip deletion

        # Check usage across all policy packages
        used_in = []
        for package in list_policy_packages(session):
            policies = get_firewall_policies(session, package)
            for policy in policies:
                pid = policy.get("policyid")
                name = policy.get("name", "Unnamed")
                src = policy.get("srcaddr", [])
                dst = policy.get("dstaddr", [])
                if group_name in src or group_name in dst:
                    used_in.append((package, pid, name))

        if used_in:
            print(f"📦 Address group '{group_name}' is empty but still used in:")
            for pkg, pid, pname in used_in:
                print(f"   - Policy ID {pid} ({pname}) in package '{pkg}'")
            # 🔁 Force re-evaluation and cleanup
            process_group(session, group_name, remove=True)
        else:
            # Safe to delete
            delete_payload = {
                "method": "delete",
                "params": [{
                    "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
                }],
                "session": session,
                "id": 1
            }
            requests.post(f"{FMG_HOST}/jsonrpc", json=delete_payload, verify=False)
            print(f"🧹 Deleted empty and unused address group '{group_name}'")
    except Exception:
        print(f"⚠️ Failed to evaluate or delete group '{group_name}'")
        
def remove_from_address_groups(session, obj_name):
    groups = find_address_groups(session, obj_name)
    for group_name in groups:
        url = f"{FMG_HOST}/jsonrpc"
        payload = {
            "method": "get",
            "params": [{
                "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}"
            }],
            "session": session,
            "id": 1
        }
        response = requests.post(url, json=payload, verify=False)
        result = response.json()
        try:
            members = result["result"][0]["data"]["member"]
            if obj_name in members:
                members.remove(obj_name)
                update_payload = {
                    "method": "update",
                    "params": [{
                        "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{group_name}",
                        "data": {"member": members}
                    }],
                    "session": session,
                    "id": 1
                }
                requests.post(f"{FMG_HOST}/jsonrpc", json=update_payload, verify=False)
                print(f"🧹 Removed '{obj_name}' from address group '{group_name}'")
                check_and_cleanup_group_usage(session, group_name)
        except Exception:
            print(f"⚠️ Failed to update group '{group_name}'")

def cleanup_empty_unused_groups(session):
    url = f"{FMG_HOST}/jsonrpc"
    payload = {
        "method": "get",
        "params": [{
            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp"
        }],
        "session": session,
        "id": 1
    }
    response = requests.post(url, json=payload, verify=False)
    result = response.json()

    try:
        groups = result["result"][0]["data"]
        for group in groups:
            name = group["name"]
            members = group.get("member", [])
            if not members:
                # Check if group is used in any policy
                used = False
                for package in list_policy_packages(session):
                    policies = get_firewall_policies(session, package)
                    for policy in policies:
                        if name in policy.get("srcaddr", []) or name in policy.get("dstaddr", []):
                            used = True
                            break
                    if used:
                        break
                if not used:
                    # Delete the group
                    delete_payload = {
                        "method": "delete",
                        "params": [{
                            "url": f"/pm/config/adom/{ADOM}/obj/firewall/addrgrp/{name}"
                        }],
                        "session": session,
                        "id": 1
                    }
                    requests.post(f"{FMG_HOST}/jsonrpc", json=delete_payload, verify=False)
                    print(f"🧹 Deleted empty and unused address group '{name}'")
    except Exception:
        print("⚠️ Failed to process address groups for recursive cleanup.")

def main():
    global FMG_HOST, USERNAME, PASSWORD

    # for unattended mode, comment these next 3 lines, and use variables at the top
    FMG_HOST = input("FortiManager IP or hostname (e.g., https://192.168.1.52): ").strip()
    USERNAME = input("Username: ").strip()
    PASSWORD = getpass.getpass("Password: ")

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
        for name in all_objects:
            obj_type = get_object_type(session, name)
            if obj_type == "address":
                process_object(session, name, remove=args.remove)
            elif obj_type == "group":
                process_group(session, name, remove=args.remove)
            else:
                print(f"❌ Object or group '{name}' not found in FortiManager.")
    finally:
        logout(session)

if __name__ == "__main__":
    main()
