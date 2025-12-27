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
//!     #[setting(label = "Enable Tray")]
//!     tray_enabled: bool,
//!
//!     #[setting(label = "Port", min = 1024, max = 65535)]
//!     port: u16,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Expr, Fields, Lit, Meta, Type};

/// Derive macro for generating `SettingsSchema` implementations.
///
/// # Attributes
///
/// ## Container attributes (`#[schema(...)]`)
/// - `category = "name"` - Default category for all fields
///
/// ## Field attributes (`#[setting(...)]`)
/// - `label = "Label"` - Display label (required or auto-generated)
/// - `description = "..."` - Help text
/// - `category = "..."` - Category override
/// - `min = 0.0` - Minimum value (for numbers)
/// - `max = 100.0` - Maximum value (for numbers)  
/// - `step = 1.0` - Step increment (for numbers)
/// - `options = [("value", "Label"), ...]` - Options for select type
/// - `secret` - Mark as secret (stored in keychain)
/// - `advanced` - Mark as advanced/experimental
/// - `requires_restart` - Mark as requiring app restart
/// - `skip` - Skip this field from schema
#[proc_macro_derive(SettingsSchema, attributes(schema, setting))]
pub fn derive_settings_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let container_attrs = parse_container_attrs(&input.attrs);

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "SettingsSchema can only be derived for structs with named fields.\n\nExample:\n  #[derive(SettingsSchema)]\n  struct MySettings {\n      field: Type,\n  }"
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input,
                "SettingsSchema can only be derived for structs.\n\nTry: #[derive(SettingsSchema)] on a struct, not an enum or union."
            )
            .to_compile_error()
            .into();
        }
    };

    let mut metadata_entries = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;
        let attrs = parse_field_attrs(&field.attrs);

        // Skip fields marked with #[setting(skip)]
        if attrs.skip {
            continue;
        }

        // Check if this is a nested struct (not a primitive type)
        if is_nested_struct(field_type) {
            // For nested structs, we expect them to also implement SettingsSchema
            let prefix = field_name.to_string();
            metadata_entries.push(quote! {
                // Merge nested struct's metadata with prefix
                // Keys from nested struct are "category.field_name", we extract just "field_name"
                for (key, mut meta) in <#field_type as rcman::SettingsSchema>::get_metadata() {
                    // Extract just the field name (part after last dot)
                    let field_only = key.rsplit('.').next().unwrap_or(&key);
                    let prefixed_key = format!("{}.{}", #prefix, field_only);
                    // Override category with the prefix (parent field name)
                    meta.category = Some(#prefix.to_string());
                    map.insert(prefixed_key, meta);
                }
            });
            continue;
        }

        // Generate the key: "category.field_name"
        let category = attrs
            .category
            .as_ref()
            .or(container_attrs.category.as_ref())
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        let key = format!("{}.{}", category, field_name);

        // Generate label (use provided or capitalize field name)
        let label = attrs.label.clone().unwrap_or_else(|| {
            field_name
                .to_string()
                .split('_')
                .map(|s| {
                    let mut c = s.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        });

        // Determine setting type from Rust type (or use select if options provided)
        let setting_constructor = if !attrs.options.is_empty() {
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
                    #label,
                    defaults.#field_name.clone(),
                    vec![#(#options),*]
                )
            }
        } else {
            let (constructor, _default_expr) =
                generate_setting_type(field_type, &label, field_name);
            constructor
        };

        // Build the metadata with chainable modifiers
        let mut modifiers = Vec::new();

        modifiers.push(quote! { .category(#category) });

        if let Some(desc) = &attrs.description {
            modifiers.push(quote! { .description(#desc) });
        }
        if let Some(min) = attrs.min {
            modifiers.push(quote! { .min(#min) });
        }
        if let Some(max) = attrs.max {
            modifiers.push(quote! { .max(#max) });
        }
        if let Some(step) = attrs.step {
            modifiers.push(quote! { .step(#step) });
        }
        if attrs.secret {
            modifiers.push(quote! { .secret() });
        }
        if attrs.advanced {
            modifiers.push(quote! { .advanced() });
        }
        if attrs.requires_restart {
            modifiers.push(quote! { .requires_restart() });
        }

        metadata_entries.push(quote! {
            map.insert(
                #key.to_string(),
                { #setting_constructor } #(#modifiers)*
            );
        });
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

/// Container-level attributes from #[schema(...)]
#[derive(Default)]
struct ContainerAttrs {
    category: Option<String>,
}

/// Field-level attributes from #[setting(...)]
#[derive(Default)]
struct FieldAttrs {
    label: Option<String>,
    description: Option<String>,
    category: Option<String>,
    min: Option<f64>,
    max: Option<f64>,
    step: Option<f64>,
    options: Vec<(String, String)>, // (value, label) pairs for select type
    secret: bool,
    advanced: bool,
    requires_restart: bool,
    skip: bool,
}

fn parse_container_attrs(attrs: &[Attribute]) -> ContainerAttrs {
    let mut result = ContainerAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("schema") {
            if let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) {
                for meta in nested {
                    if let Meta::NameValue(nv) = meta {
                        if nv.path.is_ident("category") {
                            if let Expr::Lit(lit) = &nv.value {
                                if let Lit::Str(s) = &lit.lit {
                                    result.category = Some(s.value());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

fn parse_field_attrs(attrs: &[Attribute]) -> FieldAttrs {
    let mut result = FieldAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("setting") {
            if let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) {
                for meta in nested {
                    match meta {
                        Meta::Path(path) => {
                            if path.is_ident("secret") {
                                result.secret = true;
                            } else if path.is_ident("advanced") {
                                result.advanced = true;
                            } else if path.is_ident("requires_restart") {
                                result.requires_restart = true;
                            } else if path.is_ident("skip") {
                                result.skip = true;
                            }
                        }
                        Meta::NameValue(nv) => {
                            let value = &nv.value;
                            if nv.path.is_ident("label") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Str(s) = &lit.lit {
                                        result.label = Some(s.value());
                                    } else {
                                        panic!("#[setting(label)] must be a string literal.\n\nExample: #[setting(label = \"My Label\")]");
                                    }
                                } else {
                                    panic!("#[setting(label)] must be a string literal.\n\nExample: #[setting(label = \"My Label\")]");
                                }
                            } else if nv.path.is_ident("description") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Str(s) = &lit.lit {
                                        result.description = Some(s.value());
                                    } else {
                                        panic!("#[setting(description)] must be a string literal.\n\nExample: #[setting(description = \"Help text\")]");
                                    }
                                } else {
                                    panic!("#[setting(description)] must be a string literal.\n\nExample: #[setting(description = \"Help text\")]");
                                }
                            } else if nv.path.is_ident("category") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Str(s) = &lit.lit {
                                        result.category = Some(s.value());
                                    }
                                }
                            } else if nv.path.is_ident("min") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Float(f) = &lit.lit {
                                        result.min = f.base10_parse().ok();
                                    } else if let Lit::Int(i) = &lit.lit {
                                        result.min = i.base10_parse::<i64>().ok().map(|v| v as f64);
                                    } else {
                                        panic!("#[setting(min)] must be a number.\n\nExample: #[setting(min = 0)]");
                                    }
                                } else {
                                    panic!("#[setting(min)] must be a number.\n\nExample: #[setting(min = 0)]");
                                }
                            } else if nv.path.is_ident("max") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Float(f) = &lit.lit {
                                        result.max = f.base10_parse().ok();
                                    } else if let Lit::Int(i) = &lit.lit {
                                        result.max = i.base10_parse::<i64>().ok().map(|v| v as f64);
                                    } else {
                                        panic!("#[setting(max)] must be a number.\n\nExample: #[setting(max = 100)]");
                                    }
                                }
                            } else if nv.path.is_ident("step") {
                                if let Expr::Lit(lit) = value {
                                    if let Lit::Float(f) = &lit.lit {
                                        result.step = f.base10_parse().ok();
                                    } else if let Lit::Int(i) = &lit.lit {
                                        result.step =
                                            i.base10_parse::<i64>().ok().map(|v| v as f64);
                                    }
                                }
                            }
                        }
                        Meta::List(list) => {
                            // Handle options = [("val", "Label"), ...]
                            if list.path.is_ident("options") {
                                if let Ok(items) = list.parse_args_with(
                                    syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
                                ) {
                                    for item in items {
                                        if let Expr::Tuple(tuple) = item {
                                            if tuple.elems.len() == 2 {
                                                let mut vals = tuple.elems.iter();
                                                if let (Some(Expr::Lit(v)), Some(Expr::Lit(l))) =
                                                    (vals.next(), vals.next())
                                                {
                                                    if let (Lit::Str(val), Lit::Str(label)) =
                                                        (&v.lit, &l.lit)
                                                    {
                                                        result.options.push((val.value(), label.value()));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result
}

/// Check if a type is likely a nested struct (not a primitive)
fn is_nested_struct(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            // Primitive types are not nested structs
            !matches!(
                name.as_str(),
                "bool"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "f32"
                    | "f64"
                    | "char"
                    | "str"
                    | "String"
            )
        } else {
            // Has path segments like Vec<T>, Option<T>, etc.
            // These are not nested structs for our purposes
            false
        }
    } else {
        false
    }
}

/// Generate the appropriate SettingMetadata constructor based on type
fn generate_setting_type(
    ty: &Type,
    label: &str,
    field_name: &syn::Ident,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    if let Type::Path(path) = ty {
        if let Some(ident) = path.path.get_ident() {
            let name = ident.to_string();
            match name.as_str() {
                "bool" => {
                    return (
                        quote! { rcman::SettingMetadata::toggle(#label, defaults.#field_name) },
                        quote! { defaults.#field_name },
                    );
                }
                "String" => {
                    return (
                        quote! { rcman::SettingMetadata::text(#label, defaults.#field_name.clone()) },
                        quote! { defaults.#field_name.clone() },
                    );
                }
                "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64" | "usize" | "isize" => {
                    return (
                        quote! { rcman::SettingMetadata::number(#label, defaults.#field_name as f64) },
                        quote! { defaults.#field_name as f64 },
                    );
                }
                "f32" | "f64" => {
                    return (
                        quote! { rcman::SettingMetadata::number(#label, defaults.#field_name as f64) },
                        quote! { defaults.#field_name as f64 },
                    );
                }
                _ => {}
            }
        }
    }

    // Default to text for unknown types
    (
        quote! { rcman::SettingMetadata::text(#label, format!("{:?}", defaults.#field_name)) },
        quote! { format!("{:?}", defaults.#field_name) },
    )
}
