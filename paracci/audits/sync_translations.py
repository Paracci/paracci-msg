import os
import json

def sync_keys(source_dict, target_dict):
    """Recursively synchronize keys from source_dict into target_dict.
    If a key is missing in target_dict, copies it from source_dict.
    If keys are nested dictionaries, syncs them recursively.
    """
    updated = False
    for key, value in source_dict.items():
        if key not in target_dict:
            target_dict[key] = value
            updated = True
        elif isinstance(value, dict):
            if not isinstance(target_dict[key], dict):
                target_dict[key] = {}
                updated = True
            sub_updated = sync_keys(value, target_dict[key])
            if sub_updated:
                updated = True
    return updated

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    i18n_dir = os.path.join(os.path.dirname(script_dir), 'app', 'i18n')
    
    source_file = os.path.join(i18n_dir, 'en.json')
    if not os.path.exists(source_file):
        print(f"Source file {source_file} not found!")
        return

    with open(source_file, 'r', encoding='utf-8') as f:
        source_data = json.load(f)

    for filename in os.listdir(i18n_dir):
        if filename.endswith('.json') and filename != 'en.json':
            target_file = os.path.join(i18n_dir, filename)
            with open(target_file, 'r', encoding='utf-8') as f:
                target_data = json.load(f)
            
            print(f"Syncing {filename}...")
            if sync_keys(source_data, target_data):
                with open(target_file, 'w', encoding='utf-8') as f:
                    json.dump(target_data, f, indent=2, ensure_ascii=False)
                print(f"  [+] Updated {filename}")
            else:
                print(f"  [=] No missing keys in {filename}")

if __name__ == '__main__':
    main()
