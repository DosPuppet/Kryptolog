import shutil
import json
import os

DIST_DIR = 'dist'
RELEASES_DIR = 'releases'
MANIFEST_PATH = os.path.join(DIST_DIR, 'manifest.json')
BACKUP_MANIFEST = os.path.join(DIST_DIR, 'manifest.json.bak')

os.makedirs(RELEASES_DIR, exist_ok=True)

# 1. Package Chrome/Edge (Standard Manifest)
print("Packaging Chrome & Edge...")
shutil.make_archive(os.path.join(RELEASES_DIR, 'trustkeys-chrome'), 'zip', DIST_DIR)
shutil.copy(os.path.join(RELEASES_DIR, 'trustkeys-chrome.zip'), os.path.join(RELEASES_DIR, 'trustkeys-edge.zip'))

# 2. Modify Manifest for Firefox
print("Modifying manifest for Firefox...")
shutil.copy(MANIFEST_PATH, BACKUP_MANIFEST)

with open(MANIFEST_PATH, 'r') as f:
    data = json.load(f)

# Convert service_worker to scripts
if 'background' in data and 'service_worker' in data['background']:
    sw_path = data['background']['service_worker']
    del data['background']['service_worker']
    data['background']['scripts'] = [sw_path]
    # Firefox requires type="module" if using ES modules, usually preserved.
    # Ensure Gecko ID is there (it is in source)

with open(MANIFEST_PATH, 'w') as f:
    json.dump(data, f, indent=4)

# 3. Package Firefox
print("Packaging Firefox...")
shutil.make_archive(os.path.join(RELEASES_DIR, 'trustkeys-firefox'), 'zip', DIST_DIR)

# 4. Restore Manifest
print("Cleaning up...")
shutil.move(BACKUP_MANIFEST, MANIFEST_PATH)

print("Done! Packages in releases/")
