# TODO

## Future Improvements (Post v0.1.2)

- [ ] **Type-Safe Setting Accessors via Derive Macro**
    - Currently users must call `manager.get::<T>("category.key")?`.
    - The goal is to generate typed accessors like `settings.ui_theme()` via the `SettingsSchema` derive macro.
    - This would eliminate magic strings and provide better IDE autocomplete.
