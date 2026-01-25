//! Derive macros for rcman settings library
//!
//! This crate provides `#[derive(SettingsSchema)]` for automatically generating
//! settings schema implementations.
//!
//! # Usage
//!
//! ```text
//! use rcman::SettingsSchema;
//!
//! #[derive(SettingsSchema, Default, Serialize, Deserialize)]
//! #[schema(category = "general")]
//! struct GeneralSettings {
//!     tray_enabled: bool,
//!
//!     #[setting(min = 1024, max = 65535)]
//!     port: u16,
//!
//!     #[setting(
//!         pattern = r"^[\w.-]+@[\w.-]+\.\w+$",
//!         label = "Email Address"
//!     )]
//!     email: String,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Expr, Field, Fields, Lit, Meta, Type, parse_macro_input};

/// Derive macro for generating `SettingsSchema` implementations.
///
/// # Attributes
///
/// ## Container attributes (`#[schema(...)]`)
/// - `category = "name"` - Required. Category for all fields
///
/// ## Field attributes (`#[setting(...)]`)
/// - `category = "..."` - Category override (optional)
/// - `min = 0.0` - Minimum value (for numbers)
/// - `max = 100.0` - Maximum value (for numbers)  
/// - `step = 1.0` - Step increment (for numbers)
/// - `pattern = "regex"` - Regex pattern for text validation
/// - `options = [("value", "Label"), ...]` - Options for select type
/// - `secret` - Mark as secret (stored in keychain)
/// - `nested` - Explicitly mark field as nested struct (optional, auto-detected)
/// - `skip` - Skip this field from schema
///
/// **Dynamic Metadata**: Any other `key = value` pairs are automatically converted to metadata:
/// - String literals → `.meta_str(key, value)`
/// - Number literals → `.meta_num(key, value)`
/// - Boolean literals → `.meta_bool(key, value)`
///
/// ```text
/// #[setting(
///     min = 1024,
///     max = 65535,
///     label = "Server Port",           // -> .meta_str("label", "Server Port")
///     description = "API port",        // -> .meta_str("description", "API port")
///     order = 1,                        // -> .meta_num("order", 1)
///     advanced = false,                 // -> .meta_bool("advanced", false)
///     my_custom_key = "anything"        // -> .meta_str("my_custom_key", "anything")
/// )]
/// port: u16,
/// ```
///
/// Note: For UI metadata like label and description, use `.meta_str()` manually after schema generation.
///
/// # Panics
///
/// This macro generates compile errors (not runtime panics) if:
/// - The derive is used on non-struct types or structs without named fields
/// - Category is missing (not provided in #[schema] or #[setting])
/// - Attributes have invalid values (e.g., `min` with non-numeric literal)
#[proc_macro_derive(SettingsSchema, attributes(schema, setting))]
pub fn derive_settings_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let container_attrs = match parse_container_attrs(&input.attrs) {
        Ok(attrs) => attrs,
        Err(e) => return e.to_compile_error().into(),
    };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "SettingsSchema can only be derived for structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input,
                "SettingsSchema can only be derived for structs, not enums or unions",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut metadata_entries = Vec::new();

    for field in fields {
        let attrs = match parse_field_attrs(&field.attrs) {
            Ok(attrs) => attrs,
            Err(e) => return e.to_compile_error().into(),
        };
        if attrs.skip {
            continue;
        }

        let entry = process_field(field, &attrs, &container_attrs);
        metadata_entries.push(entry);
    }

    let expanded = quote! {
        impl rcman::SettingsSchema for #name {
            fn get_metadata() -> std::collections::HashMap<String, rcman::SettingMetadata> {
                let defaults = <#name as Default>::default();
                let mut map = std::collections::HashMap::new();
                #(#metadata_entries)*
                map
            }
        }
    };

    TokenStream::from(expanded)
}

fn process_field(
    field: &Field,
    attrs: &FieldAttrs,
    container_attrs: &ContainerAttrs,
) -> proc_macro2::TokenStream {
    let Some(field_name) = &field.ident else {
        return syn::Error::new_spanned(
            field,
            "Field must have a name (internal error: expected named field)",
        )
        .to_compile_error();
    };
    let field_type = &field.ty;

    // Check if this is a nested struct (not a primitive type)
    // Can be explicitly marked with #[setting(nested)] or auto-detected
    if attrs.nested || is_nested_struct(field_type) {
        let prefix = field_name.to_string();
        return quote! {
            // Merge nested struct's metadata with prefix
            // Keys from nested struct are "category.field_name", we extract just "field_name"
            for (key, meta) in <#field_type as rcman::SettingsSchema>::get_metadata() {
                // Extract just the field name (part after last dot)
                let field_only = key.rsplit('.').next().unwrap_or(&key);
                let prefixed_key = format!("{}.{}", #prefix, field_only);
                // Note: Category is structural (in key), not stored in metadata
                map.insert(prefixed_key, meta);
            }
        };
    }

    // Generate the key: "category.field_name"
    // Category is REQUIRED - no default fallback
    let Some(category) = attrs
        .category
        .as_ref()
        .or(container_attrs.category.as_ref())
    else {
        return syn::Error::new_spanned(
            field,
            "Category is required. Add #[schema(category = \"name\")] to the struct or #[setting(category = \"name\")] to this field"
        )
        .to_compile_error();
    };
    let key = format!("{category}.{field_name}");

    // Determine setting type from Rust type (or use select if options provided)
    let setting_constructor = if attrs.options.is_empty() {
        generate_setting_type(field_type, field_name)
    } else {
        // Generate select type with options
        let options: Vec<_> = attrs
            .options
            .iter()
            .map(|(val, lbl)| {
                quote! { rcman::SettingOption::new(#val, #lbl) }
            })
            .collect();
        quote! {
            rcman::SettingMetadata::select(
                defaults.#field_name.clone(),
                vec![#(#options),*]
            )
        }
    };

    // Build constraint modifiers (min, max, step, pattern, secret)
    // Users can add metadata (label, description, etc.) manually via .meta_str()
    let mut modifiers = Vec::new();

    if let Some(min) = attrs.min {
        modifiers.push(quote! { .min(#min) });
    }
    if let Some(max) = attrs.max {
        modifiers.push(quote! { .max(#max) });
    }
    if let Some(step) = attrs.step {
        modifiers.push(quote! { .step(#step) });
    }
    if let Some(pattern) = &attrs.pattern {
        modifiers.push(quote! { .pattern(#pattern) });
    }
    if attrs.secret {
        modifiers.push(quote! { .secret() });
    }
    if !attrs.reserved.is_empty() {
        let reserved_items = &attrs.reserved;
        modifiers.push(quote! { .reserved(vec![#(#reserved_items.to_string()),*]) });
    }

    // Add dynamic metadata modifiers
    for (key, value) in &attrs.metadata_str {
        modifiers.push(quote! { .meta_str(#key, #value) });
    }
    for (key, value) in &attrs.metadata_bool {
        modifiers.push(quote! { .meta_bool(#key, #value) });
    }
    for (key, value) in &attrs.metadata_num {
        modifiers.push(quote! { .meta_num(#key, #value) });
    }

    quote! {
        map.insert(
            #key.to_string(),
            { #setting_constructor } #(#modifiers)*
        );
    }
}

/// Container-level attributes from #[schema(...)]
#[derive(Default)]
struct ContainerAttrs {
    category: Option<String>,
}

/// Field-level attributes from #[setting(...)]
#[derive(Default)]
struct FieldAttrs {
    category: Option<String>,
    min: Option<f64>,
    max: Option<f64>,
    step: Option<f64>,
    pattern: Option<String>,
    options: Vec<(String, String)>, // (value, label) pairs for select type
    reserved: Vec<String>,
    secret: bool,
    skip: bool,
    nested: bool, // Explicit marker for nested structs
    // Dynamic metadata: any key=value that isn't a known constraint
    metadata_str: Vec<(String, String)>,
    metadata_bool: Vec<(String, bool)>,
    metadata_num: Vec<(String, f64)>,
}

fn parse_container_attrs(attrs: &[Attribute]) -> Result<ContainerAttrs, syn::Error> {
    let mut result = ContainerAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("schema") {
            let nested = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;

            for meta in nested {
                if let Meta::NameValue(nv) = meta {
                    if nv.path.is_ident("category") {
                        if let Expr::Lit(lit) = &nv.value {
                            if let Lit::Str(s) = &lit.lit {
                                result.category = Some(s.value());
                            } else {
                                return Err(syn::Error::new_spanned(
                                    lit,
                                    "#[schema(category)] must be a string literal",
                                ));
                            }
                        } else {
                            return Err(syn::Error::new_spanned(
                                &nv.value,
                                "#[schema(category)] must be a string literal, not an expression",
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Parse a numeric constraint (min, max, or step)
fn parse_number_constraint(
    lit: &syn::ExprLit,
    constraint_name: &str,
) -> Result<Option<f64>, syn::Error> {
    match &lit.lit {
        Lit::Float(f) => Ok(f.base10_parse().ok()),
        Lit::Int(i) => Ok(i.base10_parse().ok()),
        Lit::Str(_) => Err(syn::Error::new_spanned(
            lit,
            format!(
                "#[setting({constraint_name})] expects a number, found string literal (hint: remove quotes, use `{constraint_name} = 10`)"
            ),
        )),
        Lit::Bool(_) => Err(syn::Error::new_spanned(
            lit,
            format!(
                "#[setting({constraint_name})] expects a number, found boolean (hint: use `{constraint_name} = 10`)"
            ),
        )),
        _ => Err(syn::Error::new_spanned(
            lit,
            format!(
                "#[setting({constraint_name})] must be a number literal (e.g., `{constraint_name} = 10` or `{constraint_name} = 10.5`)"
            ),
        )),
    }
}

/// Parse custom metadata value from literal
fn parse_metadata_value(
    key: String,
    lit: &syn::ExprLit,
    result: &mut FieldAttrs,
) -> Result<(), syn::Error> {
    match &lit.lit {
        Lit::Str(s) => {
            result.metadata_str.push((key, s.value()));
            Ok(())
        }
        Lit::Bool(b) => {
            result.metadata_bool.push((key, b.value()));
            Ok(())
        }
        Lit::Int(i) => {
            if let Ok(val) = i.base10_parse::<i64>() {
                #[allow(clippy::cast_precision_loss)]
                result.metadata_num.push((key, val as f64));
            }
            Ok(())
        }
        Lit::Float(f) => {
            if let Ok(val) = f.base10_parse::<f64>() {
                result.metadata_num.push((key, val));
            }
            Ok(())
        }
        _ => Err(syn::Error::new_spanned(
            lit,
            format!(
                "Metadata value for '{key}' must be a string, number, or boolean literal (hint: use \\\"text\\\", 123, or true/false)"
            ),
        )),
    }
}

/// Parse options list from #[setting(options = [...])]
fn parse_options_list(list: &syn::MetaList, result: &mut FieldAttrs) -> Result<(), syn::Error> {
    let items = list
        .parse_args_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)?;

    for item in items {
        let Expr::Tuple(tuple) = &item else {
            return Err(syn::Error::new_spanned(
                &item,
                "#[setting(options)] must be an array of tuples: [(\"val\", \"Label\"), ...]",
            ));
        };

        if tuple.elems.len() != 2 {
            return Err(syn::Error::new_spanned(
                tuple,
                "#[setting(options)] tuples must have exactly 2 elements: (\"value\", \"Label\")",
            ));
        }

        let mut vals = tuple.elems.iter();
        match (vals.next(), vals.next()) {
            (Some(Expr::Lit(v)), Some(Expr::Lit(l))) => match (&v.lit, &l.lit) {
                (Lit::Str(val), Lit::Str(label)) => {
                    result.options.push((val.value(), label.value()));
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        tuple,
                        "#[setting(options)] tuple elements must be string literals",
                    ));
                }
            },
            _ => {
                return Err(syn::Error::new_spanned(
                    tuple,
                    "#[setting(options)] tuple elements must be string literals",
                ));
            }
        }
    }
    Ok(())
}

fn parse_field_attrs(attrs: &[Attribute]) -> Result<FieldAttrs, syn::Error> {
    let mut result = FieldAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("setting") {
            let nested = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;

            for meta in nested {
                match meta {
                    Meta::Path(path) => {
                        if path.is_ident("secret") {
                            result.secret = true;
                        } else if path.is_ident("skip") {
                            result.skip = true;
                        } else if path.is_ident("nested") {
                            result.nested = true;
                        }
                    }
                    Meta::NameValue(nv) => {
                        let value = &nv.value;
                        if nv.path.is_ident("category") {
                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "#[setting(category)] must be a string literal, not an expression",
                                ));
                            };
                            let Lit::Str(s) = &lit.lit else {
                                return Err(syn::Error::new_spanned(
                                    lit,
                                    "#[setting(category)] must be a string literal",
                                ));
                            };
                            result.category = Some(s.value());
                        } else if nv.path.is_ident("min") {
                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "#[setting(min)] must be a number literal",
                                ));
                            };
                            result.min = parse_number_constraint(lit, "min")?;
                        } else if nv.path.is_ident("max") {
                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "#[setting(max)] must be a number literal",
                                ));
                            };
                            result.max = parse_number_constraint(lit, "max")?;
                        } else if nv.path.is_ident("step") {
                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "#[setting(step)] must be a number literal",
                                ));
                            };
                            result.step = parse_number_constraint(lit, "step")?;
                        } else if nv.path.is_ident("pattern") {
                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "#[setting(pattern)] must be a string literal",
                                ));
                            };
                            let Lit::Str(s) = &lit.lit else {
                                return Err(syn::Error::new_spanned(
                                    lit,
                                    "#[setting(pattern)] must be a string literal",
                                ));
                            };
                            result.pattern = Some(s.value());
                        } else {
                            // Unknown key - treat as custom metadata
                            let key = nv
                                .path
                                .get_ident()
                                .map(std::string::ToString::to_string)
                                .unwrap_or_default();

                            let Expr::Lit(lit) = value else {
                                return Err(syn::Error::new_spanned(
                                    value,
                                    "Metadata values must be literals, not expressions",
                                ));
                            };
                            parse_metadata_value(key, lit, &mut result)?;
                        }
                    }
                    Meta::List(list) => {
                        if list.path.is_ident("options") {
                            parse_options_list(&list, &mut result)?;
                        } else if list.path.is_ident("reserved") {
                            parse_reserved_list(&list, &mut result)?;
                        }
                    }
                }
            }
        }
    }

    Ok(result)
}

fn parse_reserved_list(list: &syn::MetaList, result: &mut FieldAttrs) -> Result<(), syn::Error> {
    let items = list
        .parse_args_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)?;

    for item in items {
        if let Expr::Lit(lit) = item {
            if let Lit::Str(s) = lit.lit {
                result.reserved.push(s.value());
            } else {
                return Err(syn::Error::new_spanned(
                    lit,
                    "#[setting(reserved)] values must be string literals",
                ));
            }
        } else {
            return Err(syn::Error::new_spanned(
                item,
                "#[setting(reserved)] values must be string literals",
            ));
        }
    }
    Ok(())
}

/// Classification of Rust types for settings generation
enum TypeInfo {
    Toggle,  // bool
    Text,    // String
    Number,  // i8, i16, i32, u32, f32, f64, etc.
    List,    // Vec<T>
    Unknown, // Everything else (may be nested struct or std type we don't handle)
}

/// Classify a type for settings schema generation
///
/// Uses a whitelist approach: known primitives/std types are classified,
/// everything else returns Unknown (could be nested struct or unsupported std type).
fn classify_type(ty: &Type) -> TypeInfo {
    if let Type::Path(path) = ty {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            match name.as_str() {
                "bool" => return TypeInfo::Toggle,
                "String" => return TypeInfo::Text,
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" | "f32" | "f64" => return TypeInfo::Number,
                // Other std types that are NOT nested structs
                "str" | "char" | "PathBuf" | "OsString" | "CString" | "Duration" | "Instant"
                | "SystemTime" | "Box" | "Rc" | "Arc" | "Cow" | "Vec" | "VecDeque" | "HashMap"
                | "HashSet" | "BTreeMap" | "BTreeSet" | "LinkedList" | "Option" | "Result" => {
                    return TypeInfo::Unknown;
                }
                _ => return TypeInfo::Unknown,
            }
        }
        // Check for Vec<T> specifically
        if let Some(seg) = path.path.segments.last() {
            if seg.ident == "Vec" {
                return TypeInfo::List;
            }
        }
        // Other complex paths (Option<T>, Result<T>, etc.)
        return TypeInfo::Unknown;
    }
    TypeInfo::Unknown
}

/// Check if a type is likely a nested struct (not a primitive)
///
/// This uses a conservative whitelist approach: known primitive/std types
/// return false, everything else is assumed to be a nested struct.
///
/// For edge cases (like `Option<MyStruct>`), use explicit `#[setting(nested)]`.
fn is_nested_struct(ty: &Type) -> bool {
    // Only simple path types with single ident can be nested
    if let Type::Path(path) = ty {
        if path.path.get_ident().is_some() {
            // Use classify_type: Unknown + simple ident = likely custom struct
            matches!(classify_type(ty), TypeInfo::Unknown)
        } else {
            // Complex paths like Vec<T>, Option<T> - not nested
            false
        }
    } else {
        // References, tuples, arrays, etc. - not nested
        false
    }
}

/// Generate the appropriate `SettingMetadata` constructor based on type
fn generate_setting_type(ty: &Type, field_name: &syn::Ident) -> proc_macro2::TokenStream {
    match classify_type(ty) {
        TypeInfo::Toggle => {
            quote! { rcman::SettingMetadata::toggle(defaults.#field_name) }
        }
        TypeInfo::Text => {
            quote! { rcman::SettingMetadata::text(defaults.#field_name.clone()) }
        }
        TypeInfo::Number => {
            quote! { rcman::SettingMetadata::number(defaults.#field_name as f64) }
        }
        TypeInfo::List => {
            quote! { rcman::SettingMetadata::list(&defaults.#field_name[..]) }
        }
        TypeInfo::Unknown => {
            // Fallback for unknown types - format as debug string
            quote! { rcman::SettingMetadata::text(format!("{:?}", defaults.#field_name)) }
        }
    }
}
