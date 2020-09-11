import argparse
import sqlite3
import time
import json
import xml.etree.ElementTree as ET
import xmltodict

PRAGMA_USER_VERSION = 'PRAGMA user_version'
USER_VERSION = 'user_version'
QUERY_ASSETS = 'SELECT RecordId, PrimaryId, AssetKey, AssetValue, n.Payload \
            FROM NotificationHandler nh  \
            LEFT JOIN HandlerAssets ha ON ha.HandlerId = nh.RecordId \
            LEFT JOIN Notification n ON nh.RecordId = n.HandlerId \
            ORDER BY RecordId'
ASSETS = "assets"
QUERY_ASSET_NOTIFICATIONS = ""

def main(args):
    start_time = time.time()
    path = args.path
    if not path:
        print("Path is required.")
        exit()
    data = process_db(path)
    # j = json.dumps(data)
    print(str(data))
    print(f'Elapsed time: {round(time.time() - start_time, 2)}s')

def process_db(file):
    db_info = {}
    try:
        db_conn = sqlite3.connect(file)
        db_conn.row_factory = sqlite3.Row
        c = db_conn.cursor()
        c.execute(PRAGMA_USER_VERSION)
        db_info[USER_VERSION] = c.fetchone()[0]
        c.execute(QUERY_ASSETS)
        asset_data = [dict(row) for row in c.fetchall()]
        # c.execute(QUERY_ASSET_NOTIFICATIONS)
        # asset_notifications = [dict(row) for row in c.fetchall()]
        db_info[ASSETS] = process_assets(asset_data)
    except Exception as e:
        db_info = None
        print(str(e))
    finally:
        c.close()
        db_conn.close()
    return db_info

def process_assets(assets):
    processed_assets = {}
    for asset in assets:
        id = asset["RecordId"]
        if id in processed_assets:
            # Not new asset
            process_asset_key(asset, processed_assets[id])
            process_notification(asset, dict_asset)
        else:
            # New asset
            dict_asset = {}
            dict_asset["HandlerId"] = id
            dict_asset["HandlerPrimaryId"] = asset["PrimaryId"]
            dict_asset["OtherAssets"] = []
            dict_asset["Notifications"] = []
            process_asset_key(asset, dict_asset)
            process_notification(asset, dict_asset)

            processed_assets[id] = dict_asset

    return processed_assets

def process_asset_key(asset, dict_asset):
    if "AssetKey" not in asset:
        return
    asset_key = asset["AssetKey"]
    if asset_key == "DisplayName":
        dict_asset["AppName"] = asset["AssetValue"]
    elif asset_key:
        asset_pair = {asset_key: asset["AssetValue"]}
        if asset_pair not in dict_asset["OtherAssets"]:
            dict_asset["OtherAssets"].append(asset_pair)
        
def process_notification(asset, dict_asset):
    if "Payload" not in asset:
        return
    payload = asset["Payload"]
    if payload:
        dict_asset["Notifications"].append(xmltodict.parse(payload))

def setup_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', type=str, help='Path to Notifications DB (wpndatabase.db)')
    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    main(args)