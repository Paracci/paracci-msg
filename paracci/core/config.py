import os
import json

from .logger import get_logger
logger = get_logger("Config")

class ParacciConfig:
    """Stores application settings as config.json within DATA_DIR."""
    
    DEFAULT_CONFIG = {
        "username": "Paracci User",
        "avatar_color": "#0a84ff",
        "anti_screenshot": True,
        "quiet_mode": False,
        "default_ttl": 0,
        "auto_clear_on_exit": True,
        "language": "tr",
        "theme_mode": "dark",
        "downloads_dir": "downloads", # Subfolder within DATA_DIR
        "auto_cleanup_hours": 24      # After how many hours should old files be deleted?
    }

    def __init__(self):
        """Initializes the config manager and loads settings."""
        self.data_dir = os.environ.get('DATA_DIR', 'data')
        self.config_path = os.path.join(self.data_dir, 'config.json')
        self.settings = self.DEFAULT_CONFIG.copy()
        self.load()
        
        # Create downloads folder
        self.full_downloads_path = os.path.join(self.data_dir, self.get("downloads_dir"))
        if not os.path.exists(self.full_downloads_path):
            os.makedirs(self.full_downloads_path, exist_ok=True)

    def load(self):
        """Loads settings from the config.json file."""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir, exist_ok=True)
            
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self.settings.update(loaded)
            except Exception as e:
                logger.error(f"Config load error: {e}")
        else:
            self.save()

    def save(self):
        """Saves current settings to the config.json file."""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Config save error: {e}")

    def get(self, key):
        """Returns the value of the specified setting key."""
        return self.settings.get(key, self.DEFAULT_CONFIG.get(key))

    def set(self, key, value):
        """Updates a setting value and saves it to the file."""
        self.settings[key] = value
        self.save()
