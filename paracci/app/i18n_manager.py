import json
import os
import sys
from pathlib import Path
from flask import request, session, g
import logging

logger = logging.getLogger(__name__)

try:
    from paracci.core.integrity import verify_branding, get_integrity_report, set_tampered_state
except ImportError:
    # Fallback for development environment or unpackaged state
    def verify_branding(t): 
        """Mock branding verification for development."""
        return True
    def get_integrity_report(): 
        """Mock integrity report for development."""
        return {}
    def set_tampered_state(s): 
        """Mock tamper state setter for development."""
        pass

class I18nManager:
    """Class that manages multi-language (i18n) support for the Flask application."""
    def __init__(self, app=None):
        """Initializes the i18n manager."""
        self.app = app
        self.translations = {}
        self.default_locale = 'en'
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Configures the Flask application with i18n support."""
        self.app = app
        self.load_translations()
        
        @app.before_request
        def set_locale():
            """Determines the user's language preference before each request."""
            # Priority: Session > Header > Default
            locale = session.get('locale')
            if not locale:
                locale = request.accept_languages.best_match(['tr', 'en', 'de', 'fr', 'ru', 'es']) or self.default_locale
                session['locale'] = locale
            g.locale = locale

        @app.context_processor
        def inject_i18n():
            """Injects i18n helpers and IAR integrity reports into templates."""
            # IAR System: Branding verification
            title = self.translate('base.title_bar')
            if not verify_branding(title):
                # Rebranding detected!
                g.iar_tampered = True
                set_tampered_state(True) # Notify core modules
                logger.warning("IAR: Branding mismatch detected. Original identity not found in title.")
            else:
                g.iar_tampered = False
                set_tampered_state(False)

            return dict(
                _=self.translate, 
                get_locale=lambda: g.locale,
                iar_report=get_integrity_report(),
                iar_tampered=g.iar_tampered
            )

    def load_translations(self):
        """
        Scans the i18n directory for JSON translation files and loads them into memory.
        Flattens nested JSON structures for easier key-based access.
        """
        # PyInstaller frozen bundle: files land in _MEIPASS/paracci/app/i18n
        # Development mode:          files are relative to this module's location
        if hasattr(sys, '_MEIPASS'):
            i18n_dir = os.path.join(sys._MEIPASS, 'paracci', 'app', 'i18n')
        else:
            i18n_dir = os.path.join(self.app.root_path, 'i18n')

        for file in os.listdir(i18n_dir):
            if file.endswith('.json'):
                locale = file.split('.')[0]
                with open(os.path.join(i18n_dir, file), 'r', encoding='utf-8') as f:
                    self.translations[locale] = self.flatten_dict(json.load(f))

    def flatten_dict(self, d, parent_key='', sep='.'):
        """
        Recursively flattens a nested dictionary into a single-level dictionary
        with keys joined by a separator (default: '.').
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def translate(self, key, **kwargs):
        """
        Translates a given key into the current locale.
        Supports string formatting using keyword arguments.
        """
        locale = getattr(g, 'locale', self.default_locale)
        bundle = self.translations.get(locale, self.translations.get(self.default_locale, {}))
        text = bundle.get(key, key)
        if kwargs:
            return text.format(**kwargs)
        return text

# Global instance (optional, but useful)
i18n = I18nManager()
