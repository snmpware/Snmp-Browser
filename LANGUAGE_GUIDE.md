# SNMP Browser - Language Guide

## Adding a New Language

The SNMP Browser supports multiple languages with an easy-to-extend system. Follow these steps to add a new language:

### Step 1: Edit the `languages.json` File

Open the `languages.json` file in the project root directory. The file contains all language translations in a structured JSON format.

### Step 2: Add Your Language Entry

Add a new language block under the `"languages"` key. Use the ISO 639-1 language code (e.g., "it" for Italian, "nl" for Dutch).

**Template:**
```json
"[language_code]": {
  "name": "[Language Name]",
  "translations": {
    "app_title": "[Translated text]",
    "file": "[Translated text]",
    ...
  }
}
```

**Example - Adding Italian:**
```json
"it": {
  "name": "Italiano",
  "translations": {
    "app_title": "Browser SNMP - Pronto per la Produzione",
    "file": "File",
    "tools": "Strumenti",
    "help": "Aiuto",
    ...
  }
}
```

### Step 3: Copy All Translation Keys

Make sure to include ALL translation keys from one of the existing languages (e.g., English). Currently, there are about 140+ keys that need translation:

- **Menu items**: file, tools, help, save_configuration, load_configuration, etc.
- **UI labels**: host, port, version, community, timeout, retries, etc.
- **Buttons**: save, manage, start_scan, stop, test, batch, etc.
- **Tab names**: browser, dashboard, mib_tree, trap_manager, performance
- **Messages**: error, warning, success, info, etc.
- **Dialog texts**: And many more...

### Step 4: Translate Each Value

Translate each value while keeping the key names in English (unchanged). The keys are used by the code to look up translations.

### Step 5: Test Your Translation

1. Start the SNMP Browser application
2. Go to **Help** → **Language**
3. Select your newly added language from the list
4. Click **Apply**
5. Restart the application to see all changes take effect

### Step 6: Verify All UI Elements

Check all menus, tabs, buttons, and dialogs to ensure:
- All text is properly translated
- Text fits within UI elements (some languages are more verbose)
- Special characters are displayed correctly

## Current Supported Languages

The SNMP Browser currently includes translations for:

1. **English** (en) - Default
2. **Spanish** (es) - Español
3. **French** (fr) - Français
4. **German** (de) - Deutsch
5. **Chinese Simplified** (zh) - 中文
6. **Japanese** (ja) - 日本語
7. **Portuguese** (pt) - Português
8. **Russian** (ru) - Русский
9. **Arabic** (ar) - العربية
10. **Hindi** (hi) - हिन्दी

## Translation Keys Reference

### Main Categories:

- **Application**: app_title, status, ready
- **Menus**: file, tools, help, and all menu items
- **Configuration**: snmp_configuration, snmpv3_configuration, profile settings
- **Actions**: save, load, export, import, test, scan, stop, start, refresh, reset
- **Network**: host, port, version, community, timeout, retries
- **Security**: username, auth, auth_pass, priv, priv_pass, engine_id
- **Tabs**: browser, dashboard, mib_tree, trap_manager, performance
- **Dialogs**: error, warning, success, info, ok, cancel, apply, close
- **Data Fields**: oid, value, description, timestamp, source, type, size, data
- **Operations**: add, remove, edit, delete, search, filter, copy, paste, select_all

### Format Strings

Some translation values include placeholders (e.g., `{port}`, `{count}`). Keep these placeholders unchanged:

```json
"status_active": "Status: Active (port {port})",
"traps_received": "Traps received: {count}"
```

## Best Practices

1. **Consistency**: Use consistent terminology throughout the translation
2. **Brevity**: Keep translations concise to fit in UI elements
3. **Context**: Consider the context where the text appears (menu, button, label)
4. **Special Characters**: Ensure proper encoding for special characters (UTF-8)
5. **Testing**: Always test your translation in the actual application
6. **Native Speaker**: If possible, have a native speaker review the translation

## File Structure

The `languages.json` file structure:
```json
{
  "languages": {
    "en": { ... },
    "es": { ... },
    "fr": { ... },
    ...
  }
}
```

## Technical Details

- The language system uses a `LanguageManager` class
- Translations are loaded at application startup
- Language preference is saved in `snmp_browser_config.json`
- Use `self._("key")` in the code to get translated text
- Supports string formatting with `self._("key", param=value)`

## Contributing

To contribute a new language translation:

1. Fork the repository
2. Add your language to `languages.json`
3. Test thoroughly
4. Submit a pull request with:
   - Language code and name
   - Complete translations for all keys
   - Screenshots (optional but helpful)

## Support

If you need help adding a language or find missing translations:
- Open an issue on GitHub
- Include the language you're working on
- Specify which keys need clarification

---

Thank you for helping make SNMP Browser accessible to users worldwide!
