//! Derive macros for `rcman` settings library.
//!
//! This crate provides `#[derive(SettingsSchema)]` for automatically generating
//! settings schema implementations from Rust structs and tagged enums. It translates strongly-typed
//! native Rust definitions directly into runtime `rcman::SettingMetadata`, prevents bugs
//! through compile-time semantic validation, and generates rich IDE documentation cards with zero runtime cost.
//!
//! # Features
//!
//! - **Native Type Binding**: Automatically translates `String`, `PathBuf`, integers, floats, `bool`, and `Vec<T>` into their corresponding `rcman::SettingType`.
//! - **Rich IDE `IntelliSense` Cards**: Generates clean Markdown documentation cards for `rust-analyzer` showing type, range, constraints, security, and custom metadata.
//! - **Compile-Time `const` Keys**: Generates uppercase `pub const` key constants directly on derived types (e.g. `ServerSettings::PORT = "network.port"`).
//! - **Tagged-Union `enum` Support**: Merges variant sub-schemas and generates discriminant selector metadata on enums annotated with `#[serde(tag = "...")]`.
//! - **Strict Verification**: Prevents contradictory constraints at compile time (e.g. `min > max` or `options` on `bool`).
//! - **Dynamic UI Metadata**: Every unknown attribute literal (e.g., `label = "Server"`) is automatically injected into the schema as customizable metadata.
//! - **`#[cfg]` Forwarding**: Safely obeys macro feature flags attached to struct fields.
//! - **Typed Accessors**: Generates snapshot accessors on the schema struct and a `<SchemaName>ManagerAccessors` trait for typed manager access.
//! - **Strongly-Typed `validate(&self)`**: Generates zero-overhead native validation checking numeric ranges, regex patterns, allowed dropdown options, and nested schemas directly on Rust structs.
//!
//! # Usage
//!
//! ```rust
//! use rcman::DeriveSettingsSchema as SettingsSchema;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(SettingsSchema, Default, Serialize, Deserialize)]
//! #[schema(category = "network")] // Required: sets the root prefix for the UI
//! struct NetworkSettings {
//!     /// Port used for external API connections.
//!     #[setting(
//!         label = "Server Port",
//!         description = "TCP port number",
//!         min = 1024,
//!         max = 65535,
//!         rename = "server-auth-port"
//!     )]
//!     pub port: u16,
//!
//!     #[setting(rename = "enable_tls")]
//!     pub tls: bool,
//!
//!     #[setting(rename = "server-url")]
//!     pub url: String,
//!     
//!     pub roles: Vec<String>,
//! }
//!
//! fn main() {
//!     // Compile-time generated constant with rich IDE doc card:
//!     assert_eq!(NetworkSettings::PORT, "network.server-auth-port");
//! }
//! ```
//!
//! ---
//!
//! # Attribute Reference
//!
//! ## Container Attributes (`#[schema(...)]`)
//! Apply these directly to the `struct`.
//!
//! | Attribute | Description | Required | Example |
//! |-----------|-------------|----------|---------|
//! | `category` | The root grouping prefix used for all fields. | **Yes** | `#[schema(category = "general")]` |
//!
//! ## Field Attributes (`#[setting(...)]`)
//! Apply these to individual struct fields.
//!
//! | Attribute | Type Mapping | Description | Example |
//! |-----------|--------------|-------------|---------|
//! | `rename` | *All* | Overrides the field name when constructing the schema key (`category.rename`) | `#[setting(rename = "App-Theme")]` |
//! | `skip` | *All* | Silently ignores the field; it will not appear in the settings schema | `#[setting(skip)]` |
//! | `secret` | *All* | Asserts the field contains sensitive data, diverting it to the OS Keychain backing | `#[setting(secret)]` |
//! | `category` | *All* | Overrides the container `category` specifically for this single field | `#[setting(category = "overridden")]` |
//! | `nested` | Structs | Extracts the schema from an inner struct and flattens it upward | `#[setting(nested)]` |
//! | `min` | Number | Sets a numeric minimum constraint (must be `<= max`) | `#[setting(min = 1.0)]` |
//! | `max` | Number | Sets a numeric maximum constraint (must be `>= min`) | `#[setting(max = 100.0)]` |
//! | `step` | Number | Defines valid increment stepping | `#[setting(step = 5.0)]` |
//! | `pattern` | Text | Enforces standard Regex validation string | `#[setting(pattern = "^[a-z]+$")]` |
//! | `options` | Text/Num | Enforces strict dropdown alternatives mappings | `#[setting(options(("val", "Label")))]` |
//!
//! ## Dynamic Metadata
//! Any `key = value` assignment in `#[setting(...)]` that isn't functionally reserved above is transparently forwarded into the resulting `SettingMetadata` map for your UI components to access dynamically.
//!
//! ```rust
//! use rcman::DeriveSettingsSchema as SettingsSchema;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(SettingsSchema, Default, Serialize, Deserialize)]
//! #[schema(category = "network")]
//! struct ServerSettings {
//!     #[setting(
//!         min = 1024,                  // 1. Reserved constraint
//!         label = "Server Port",       // 2. -> .meta_str("label", "Server Port")
//!         order = 1,                   // 3. -> .meta_num("order", 1)
//!         advanced = false             // 4. -> .meta_bool("advanced", false)
//!     )]
//!     pub port: u16,
//! }
//!
//! fn main() {}
//! ```
//!
//! # Panics
//!
//! This macro performs completely safe compile-time error reporting (yielding `syn::Error`) returning targeted IDE-friendly error underlines instead of panicking. It blocks:
//! - Setting `min`/`max`/`step` on non-numeric types (`bool`, `Vec`, `String`).
//! - Setting `pattern` on non-Text types (`bool`, `Vec`, `i32`).
//! - Unknown/Unsupported types missing `#[setting(skip)]` (e.g. `Duration` or `HashMap`) so that you never accidentally leak invalid config metadata to the UI.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Data, DeriveInput, Expr, Field, Fields, Lit, Meta, Type, parse_macro_input};

/// Derive macro for generating `SettingsSchema` implementations. See the crate-level documentation for full attribute reference.
#[proc_macro_derive(SettingsSchema, attributes(schema, setting))]
pub fn derive_settings_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match derive_settings_schema_impl(&input) {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

fn derive_settings_schema_impl(
    input: &DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let name = &input.ident;
    let container_attrs = parse_container_attrs(&input.attrs)?;

    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                if fields.named.is_empty() {
                    return Err(syn::Error::new_spanned(
                        input,
                        "SettingsSchema can only be derived for structs with named fields",
                    ));
                }
                derive_struct_settings_schema(name, &fields.named, &container_attrs)
            }
            _ => Err(syn::Error::new_spanned(
                input,
                "SettingsSchema can only be derived for structs with named fields",
            )),
        },
        Data::Enum(data_enum) => derive_enum_settings_schema(name, data_enum, &container_attrs),
        Data::Union(_) => Err(syn::Error::new_spanned(
            input,
            "SettingsSchema can only be derived for structs or tagged enums, not unions",
        )),
    }
}

fn derive_struct_settings_schema(
    name: &syn::Ident,
    fields: &syn::punctuated::Punctuated<Field, syn::token::Comma>,
    container_attrs: &ContainerAttrs,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let derived = build_metadata_and_accessors(fields, container_attrs)?;

    let manager_trait_name = format_ident!("{}ManagerAccessors", name);
    let metadata_entries = derived.metadata_entries;
    let snapshot_methods = derived.snapshot_methods;
    let manager_trait_methods = derived.manager_trait_methods;
    let manager_impl_methods = derived.manager_impl_methods;
    let const_keys = derived.const_keys;
    let validation_stmts = derived.validation_stmts;

    Ok(quote! {
        impl rcman::SettingsSchema for #name {
            fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
                let defaults = <#name as Default>::default();
                let mut map = rcman::IndexMap::new();
                #(#metadata_entries)*
                map
            }

            fn validate(&self) -> rcman::Result<()> {
                #(#validation_stmts)*
                Ok(())
            }
        }

        impl #name {
            #(#const_keys)*
            #(#snapshot_methods)*

            /// Validates this settings instance against compile-time schema constraints.
            pub fn validate(&self) -> rcman::Result<()> {
                <Self as rcman::SettingsSchema>::validate(self)
            }
        }

        pub trait #manager_trait_name {
            #(#manager_trait_methods)*
        }

        impl<S: rcman::StorageBackend + 'static> #manager_trait_name for rcman::SettingsManager<S, #name> {
            #(#manager_impl_methods)*
        }
    })
}

struct EnumVariantInfo {
    extend: proc_macro2::TokenStream,
    const_def: proc_macro2::TokenStream,
    const_ref: (Vec<Attribute>, syn::Ident),
}

fn process_enum_variant(v: &syn::Variant) -> Result<EnumVariantInfo, syn::Error> {
    let variant_ident = &v.ident;
    let v_attrs = parse_variant_attrs(&v.attrs);
    let cfg_attrs: Vec<_> = v
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .cloned()
        .collect();

    let syn::Fields::Unnamed(fields_unnamed) = &v.fields else {
        return Err(syn::Error::new_spanned(
            v,
            "SettingsSchema enum derive requires single-element tuple variants like `Variant(VariantType)`",
        ));
    };

    if fields_unnamed.unnamed.len() != 1 {
        return Err(syn::Error::new_spanned(
            v,
            "SettingsSchema enum derive requires exactly one inner type per variant",
        ));
    }

    let inner_type = &fields_unnamed.unnamed.first().unwrap().ty;
    let tag_value = v_attrs
        .rename
        .unwrap_or_else(|| to_snake_case(&variant_ident.to_string()));
    let label_value = v_attrs
        .label
        .unwrap_or_else(|| to_title_case(&variant_ident.to_string()));
    let const_name = format_ident!("{}", variant_ident.to_string().to_ascii_uppercase());

    let variant_doc = format!(
        "**Variant Discriminant**: `{tag_value}`\n\n- **Label**: {label_value}\n- **Inner Schema**: [`{}`]",
        quote!(#inner_type)
    );

    let extend = quote! {
        #(#cfg_attrs)*
        {
            map.extend(<#inner_type as rcman::SettingsSchema>::get_metadata());
            options.push(rcman::opt(#tag_value, #label_value));
        }
    };

    let const_def = quote! {
        #(#cfg_attrs)*
        #[doc = #variant_doc]
        pub const #const_name: &'static str = #tag_value;
    };

    Ok(EnumVariantInfo {
        extend,
        const_def,
        const_ref: (cfg_attrs, const_name),
    })
}

fn derive_enum_settings_schema(
    name: &syn::Ident,
    data_enum: &syn::DataEnum,
    container_attrs: &ContainerAttrs,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let tag_name = container_attrs
        .serde_tag
        .clone()
        .unwrap_or_else(|| "kind".to_string());

    let mut variant_extends = Vec::new();
    let mut const_variants = Vec::new();
    let mut variant_const_refs = Vec::new();

    for v in &data_enum.variants {
        let info = process_enum_variant(v)?;
        variant_extends.push(info.extend);
        const_variants.push(info.const_def);
        variant_const_refs.push(info.const_ref);
    }

    let all_variants_elements: Vec<_> = variant_const_refs
        .iter()
        .map(|(cfg, ident)| {
            quote! {
                #(#cfg)*
                Self::#ident
            }
        })
        .collect();

    const_variants.push(quote! {
        /// Array containing all variant tag discriminants defined on this enum.
        pub const ALL_KEYS: &'static [&'static str] = &[
            #(#all_variants_elements),*
        ];
    });

    let variant_validations: Vec<_> = data_enum
        .variants
        .iter()
        .map(|v| {
            let variant_ident = &v.ident;
            let cfg_attrs: Vec<_> = v
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("cfg"))
                .cloned()
                .collect();
            quote! {
                #(#cfg_attrs)*
                Self::#variant_ident(inner) => <_ as rcman::SettingsSchema>::validate(inner),
            }
        })
        .collect();

    Ok(quote! {
        impl rcman::SettingsSchema for #name {
            fn get_metadata() -> rcman::IndexMap<String, rcman::SettingMetadata> {
                let mut map = rcman::IndexMap::new();
                let mut options = Vec::new();
                #(#variant_extends)*

                let default_tag = options
                    .first()
                    .and_then(|o| o.value.as_str())
                    .unwrap_or("")
                    .to_string();
                map.insert(
                    #tag_name.to_string(),
                    rcman::SettingMetadata::select(default_tag, options)
                        .meta_str("label", "Type"),
                );

                map
            }

            fn validate(&self) -> rcman::Result<()> {
                match self {
                    #(#variant_validations)*
                }
            }
        }

        impl #name {
            #(#const_variants)*

            /// Validates this settings instance against compile-time schema constraints.
            pub fn validate(&self) -> rcman::Result<()> {
                <Self as rcman::SettingsSchema>::validate(self)
            }
        }
    })
}

struct StructDerivedComponents {
    metadata_entries: Vec<proc_macro2::TokenStream>,
    snapshot_methods: Vec<proc_macro2::TokenStream>,
    manager_trait_methods: Vec<proc_macro2::TokenStream>,
    manager_impl_methods: Vec<proc_macro2::TokenStream>,
    const_keys: Vec<proc_macro2::TokenStream>,
    validation_stmts: Vec<proc_macro2::TokenStream>,
}

fn extract_field_docs(attrs: &[Attribute]) -> Vec<String> {
    let mut docs = Vec::new();
    for attr in attrs {
        if attr.path().is_ident("doc")
            && let syn::Meta::NameValue(nv) = &attr.meta
            && let syn::Expr::Lit(lit) = &nv.value
            && let syn::Lit::Str(s) = &lit.lit
        {
            docs.push(s.value().trim().to_string());
        }
    }
    docs
}

fn generate_setting_doc_comment(
    full_key: &str,
    field: &Field,
    attrs: &FieldAttrs,
    user_docs: &[String],
) -> String {
    let mut lines = Vec::new();
    lines.push(format!("**Setting**: `{full_key}`"));
    lines.push(String::new());

    let mut has_user_doc = false;
    for doc in user_docs {
        if !doc.is_empty() {
            lines.push(doc.clone());
            has_user_doc = true;
        }
    }
    if has_user_doc {
        lines.push(String::new());
    }

    let field_ty = &field.ty;
    let ty_str = quote!(#field_ty).to_string();
    lines.push(format!("- **Type**: `{ty_str}`"));

    if let (Some(min), Some(max)) = (attrs.min, attrs.max) {
        lines.push(format!("- **Range**: `{min}` .. `{max}`"));
    } else if let Some(min) = attrs.min {
        lines.push(format!("- **Min**: `{min}`"));
    } else if let Some(max) = attrs.max {
        lines.push(format!("- **Max**: `{max}`"));
    }

    if let Some(step) = attrs.step {
        lines.push(format!("- **Step**: `{step}`"));
    }

    if let Some(pattern) = &attrs.pattern {
        lines.push(format!("- **Pattern**: `{pattern}`"));
    }

    if !attrs.options.is_empty() {
        let opts_str = attrs
            .options
            .iter()
            .map(|(val, lbl)| format!("`{val}` ({lbl})"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("- **Options**: {opts_str}"));
    }

    if attrs.secret {
        lines.push("- **Security**: OS Keychain / Encrypted Store (never plaintext).".to_string());
    } else {
        lines.push("- **Security**: Plaintext config file.".to_string());
    }

    let mut meta_items = Vec::new();
    for (k, v) in &attrs.metadata_str {
        meta_items.push(format!("`{k}` = \"{v}\""));
    }
    for (k, v) in &attrs.metadata_bool {
        meta_items.push(format!("`{k}` = {v}"));
    }
    for (k, v) in &attrs.metadata_num {
        meta_items.push(format!("`{k}` = {v}"));
    }

    if !meta_items.is_empty() {
        lines.push(format!("- **Metadata**: {}", meta_items.join(", ")));
    }

    lines.join("\n")
}

fn generate_field_const_key(
    field: &Field,
    attrs: &FieldAttrs,
    container_attrs: &ContainerAttrs,
    cfg_attrs: &[Attribute],
) -> Option<(proc_macro2::TokenStream, (Vec<Attribute>, syn::Ident))> {
    let field_name = field.ident.as_ref()?;
    let const_ident = format_ident!("{}", field_name.to_string().to_ascii_uppercase());
    let const_target = (cfg_attrs.to_vec(), const_ident.clone());
    let category = resolve_field_category(attrs, container_attrs);
    let key_name = attrs
        .rename
        .clone()
        .unwrap_or_else(|| field_name.to_string());
    let full_key = if category.is_empty() {
        key_name
    } else {
        format!("{category}.{key_name}")
    };

    let user_docs = extract_field_docs(&field.attrs);
    let doc_str = generate_setting_doc_comment(&full_key, field, attrs, &user_docs);

    let const_decl = quote! {
        #(#cfg_attrs)*
        #[doc = #doc_str]
        pub const #const_ident: &'static str = #full_key;
    };

    Some((const_decl, const_target))
}

struct SingleFieldComponents {
    const_decl: Option<proc_macro2::TokenStream>,
    const_target: Option<(Vec<Attribute>, syn::Ident)>,
    metadata_entry: proc_macro2::TokenStream,
    accessor_methods: Option<(
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
    )>,
    validation_stmt: Option<proc_macro2::TokenStream>,
}

fn process_single_struct_field(
    field: &Field,
    container_attrs: &ContainerAttrs,
    used_method_names: &mut std::collections::HashMap<String, proc_macro2::Span>,
) -> Result<Option<SingleFieldComponents>, syn::Error> {
    let attrs = parse_field_attrs(&field.attrs)?;
    if attrs.skip {
        return Ok(None);
    }

    let cfg_attrs: Vec<_> = field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .cloned()
        .collect();

    let (const_decl, const_target) = if let Some((decl, target)) =
        generate_field_const_key(field, &attrs, container_attrs, &cfg_attrs)
    {
        (Some(decl), Some(target))
    } else {
        (None, None)
    };

    let raw_entry = process_field(field, &attrs, container_attrs, &cfg_attrs)?;
    let metadata_entry = if cfg_attrs.is_empty() {
        raw_entry
    } else {
        quote! {
            #(#cfg_attrs)*
            {
                #raw_entry
            }
        }
    };

    let accessor_methods = generate_accessor_methods(
        field,
        &attrs,
        container_attrs,
        &cfg_attrs,
        used_method_names,
    )?;

    let validation_stmt = generate_field_validation(field, &attrs, &cfg_attrs);

    Ok(Some(SingleFieldComponents {
        const_decl,
        const_target,
        metadata_entry,
        accessor_methods,
        validation_stmt,
    }))
}

fn build_metadata_and_accessors(
    fields: &syn::punctuated::Punctuated<Field, syn::token::Comma>,
    container_attrs: &ContainerAttrs,
) -> Result<StructDerivedComponents, syn::Error> {
    let mut metadata_entries = Vec::new();
    let mut snapshot_methods = Vec::new();
    let mut manager_trait_methods = Vec::new();
    let mut manager_impl_methods = Vec::new();
    let mut const_keys = Vec::new();
    let mut const_key_refs = Vec::new();
    let mut validation_stmts = Vec::new();
    let mut used_method_names = std::collections::HashMap::<String, proc_macro2::Span>::new();
    let mut errors = None::<syn::Error>;

    for field in fields {
        match process_single_struct_field(field, container_attrs, &mut used_method_names) {
            Ok(Some(comp)) => {
                if let (Some(decl), Some(target)) = (comp.const_decl, comp.const_target) {
                    const_keys.push(decl);
                    const_key_refs.push(target);
                }
                metadata_entries.push(comp.metadata_entry);
                if let Some((snap, mgr_trait, mgr_impl)) = comp.accessor_methods {
                    snapshot_methods.push(snap);
                    manager_trait_methods.push(mgr_trait);
                    manager_impl_methods.push(mgr_impl);
                }
                if let Some(stmt) = comp.validation_stmt {
                    validation_stmts.push(stmt);
                }
            }
            Ok(None) => {}
            Err(e) => {
                if let Some(ref mut combined) = errors {
                    combined.combine(e);
                } else {
                    errors = Some(e);
                }
            }
        }
    }

    if let Some(err) = errors {
        return Err(err);
    }

    let all_keys_elements: Vec<_> = const_key_refs
        .iter()
        .map(|(cfg, ident)| {
            quote! {
                #(#cfg)*
                Self::#ident
            }
        })
        .collect();

    const_keys.push(quote! {
        /// Array containing all compile-time schema keys defined on this struct.
        pub const ALL_KEYS: &'static [&'static str] = &[
            #(#all_keys_elements),*
        ];
    });

    Ok(StructDerivedComponents {
        metadata_entries,
        snapshot_methods,
        manager_trait_methods,
        manager_impl_methods,
        const_keys,
        validation_stmts,
    })
}

fn generate_number_checks(
    attrs: &FieldAttrs,
    const_ident: &syn::Ident,
    inner_ty: &syn::Type,
) -> Vec<proc_macro2::TokenStream> {
    let mut checks = Vec::new();
    if let Some(min) = attrs.min {
        let min_lit = proc_macro2::Literal::f64_unsuffixed(min);
        checks.push(quote! {
            if val < (#min_lit as #inner_ty) {
                return Err(rcman::Error::InvalidSettingValue {
                    key: Self::#const_ident.to_string(),
                    reason: format!("Value ({}) must be at least {}", val, #min_lit),
                });
            }
        });
    }
    if let Some(max) = attrs.max {
        let max_lit = proc_macro2::Literal::f64_unsuffixed(max);
        checks.push(quote! {
            if val > (#max_lit as #inner_ty) {
                return Err(rcman::Error::InvalidSettingValue {
                    key: Self::#const_ident.to_string(),
                    reason: format!("Value ({}) must be at most {}", val, #max_lit),
                });
            }
        });
    }
    checks
}

fn generate_text_checks(
    attrs: &FieldAttrs,
    const_ident: &syn::Ident,
) -> Vec<proc_macro2::TokenStream> {
    let mut checks = Vec::new();
    if let Some(pattern) = &attrs.pattern {
        checks.push(quote! {
            let re = rcman::regex::Regex::new(#pattern)
                .map_err(|e| rcman::Error::Config(format!("Invalid regex pattern: {e}")))?;
            if !re.is_match(text.as_str()) {
                return Err(rcman::Error::InvalidSettingValue {
                    key: Self::#const_ident.to_string(),
                    reason: format!("Value does not match pattern: {}", #pattern),
                });
            }
        });
    }
    if !attrs.options.is_empty() {
        let allowed_values: Vec<&str> = attrs.options.iter().map(|(v, _)| v.as_str()).collect();
        checks.push(quote! {
            const ALLOWED_OPTIONS: &[&str] = &[#(#allowed_values),*];
            if !ALLOWED_OPTIONS.contains(&text.as_str()) {
                return Err(rcman::Error::InvalidSettingValue {
                    key: Self::#const_ident.to_string(),
                    reason: "Value must be one of the available options".to_string(),
                });
            }
        });
    }
    checks
}

fn generate_field_validation(
    field: &Field,
    attrs: &FieldAttrs,
    cfg_attrs: &[Attribute],
) -> Option<proc_macro2::TokenStream> {
    let field_name = field.ident.as_ref()?;
    let const_ident = format_ident!("{}", field_name.to_string().to_ascii_uppercase());
    let field_type = &field.ty;

    // Check if structural / nested struct
    let is_structural = match attrs.nesting {
        Nesting::Flatten | Nesting::Nested => true,
        Nesting::Object => false,
        Nesting::Auto => is_nested_struct(field_type),
    };

    if is_structural {
        let is_opt = extract_inner_type_from_option(field_type).is_some();
        let check = if is_opt {
            quote! {
                if let Some(ref nested) = self.#field_name {
                    rcman::SettingsSchema::validate(nested)?;
                }
            }
        } else {
            quote! {
                rcman::SettingsSchema::validate(&self.#field_name)?;
            }
        };

        return Some(quote! {
            #(#cfg_attrs)*
            {
                #check
            }
        });
    }

    let is_opt = extract_inner_type_from_option(field_type).is_some();
    let inner_ty = extract_inner_type_from_option(field_type).unwrap_or(field_type);
    let type_info = classify_type(inner_ty);

    let checks = match type_info {
        TypeInfo::Number => generate_number_checks(attrs, &const_ident, inner_ty),
        TypeInfo::Text => generate_text_checks(attrs, &const_ident),
        _ => Vec::new(),
    };

    if checks.is_empty() {
        return None;
    }

    let validation_block = match type_info {
        TypeInfo::Number => {
            if is_opt {
                quote! {
                    if let Some(val) = self.#field_name {
                        #(#checks)*
                    }
                }
            } else {
                quote! {
                    let val = self.#field_name;
                    #(#checks)*
                }
            }
        }
        TypeInfo::Text => {
            if is_opt {
                quote! {
                    if let Some(ref text) = self.#field_name {
                        #(#checks)*
                    }
                }
            } else {
                quote! {
                    let text = &self.#field_name;
                    #(#checks)*
                }
            }
        }
        _ => quote! {},
    };

    Some(quote! {
        #(#cfg_attrs)*
        {
            #validation_block
        }
    })
}

fn generate_accessor_methods(
    field: &Field,
    attrs: &FieldAttrs,
    container_attrs: &ContainerAttrs,
    cfg_attrs: &[Attribute],
    used_method_names: &mut std::collections::HashMap<String, proc_macro2::Span>,
) -> Result<
    Option<(
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
    )>,
    syn::Error,
> {
    let Some(field_name) = &field.ident else {
        return Err(syn::Error::new_spanned(
            field,
            "Field must have a name (internal error: expected named field)",
        ));
    };

    let is_structural = match attrs.nesting {
        Nesting::Flatten | Nesting::Nested => true,
        Nesting::Object => false,
        Nesting::Auto => is_nested_struct(&field.ty),
    };

    if is_structural {
        return Ok(None);
    }

    let category = resolve_field_category(attrs, container_attrs);
    let key_name = attrs
        .rename
        .clone()
        .unwrap_or_else(|| field_name.to_string());

    let getter_name_str = if category.is_empty() {
        sanitize_ident_component(&field_name.to_string())
    } else {
        format!(
            "{}_{}",
            sanitize_ident_component(&category),
            sanitize_ident_component(&field_name.to_string())
        )
    };

    register_method_name(used_method_names, &getter_name_str, field_name.span())?;

    let setter_name_str = format!("set_{getter_name_str}");
    register_method_name(used_method_names, &setter_name_str, field_name.span())?;

    let getter_name = format_ident!("{getter_name_str}");
    let setter_name = format_ident!("{setter_name_str}");
    let field_type = &field.ty;
    let full_key = if category.is_empty() {
        key_name.clone()
    } else {
        format!("{category}.{key_name}")
    };

    let user_docs = extract_field_docs(&field.attrs);
    let doc_str = generate_setting_doc_comment(&full_key, field, attrs, &user_docs);
    let snap_read_doc = format!("Get the in-memory value of `{full_key}`.\n\n{doc_str}");
    let snap_write_doc =
        format!("Set the in-memory value of `{full_key}` (does not persist to disk).\n\n{doc_str}");

    let snapshot_method = quote! {
        #(#cfg_attrs)*
        #[doc = #snap_read_doc]
        pub fn #getter_name(&self) -> &#field_type {
            &self.#field_name
        }

        #(#cfg_attrs)*
        #[doc = #snap_write_doc]
        pub fn #setter_name(&mut self, value: #field_type) {
            self.#field_name = value;
        }
    };

    // Empty-category schemas are valid in rcman (for flat key maps such as
    // sub-settings schemas). Manager accessors cannot be generated for them
    // because save_setting() requires category/key split.
    if category.is_empty() {
        return Ok(Some((snapshot_method, quote! {}, quote! {})));
    }

    let mgr_read_doc =
        format!("Read setting `{full_key}` directly from the settings manager.\n\n{doc_str}");
    let mgr_write_doc =
        format!("Persist setting `{full_key}` directly to storage / keychain.\n\n{doc_str}");

    let manager_trait_method = quote! {
        #(#cfg_attrs)*
        #[doc = #mgr_read_doc]
        fn #getter_name(&self) -> rcman::Result<#field_type>;
        #(#cfg_attrs)*
        #[doc = #mgr_write_doc]
        fn #setter_name(&self, value: #field_type) -> rcman::Result<()>;
    };

    let manager_impl_method = quote! {
        #(#cfg_attrs)*
        fn #getter_name(&self) -> rcman::Result<#field_type> {
            self.get::<#field_type>(#full_key)
        }

        #(#cfg_attrs)*
        fn #setter_name(&self, value: #field_type) -> rcman::Result<()> {
            self.save_setting(#category, #key_name, &rcman::serde_json::json!(value))
        }
    };

    Ok(Some((
        snapshot_method,
        manager_trait_method,
        manager_impl_method,
    )))
}

fn register_method_name(
    used_method_names: &mut std::collections::HashMap<String, proc_macro2::Span>,
    method_name: &str,
    span: proc_macro2::Span,
) -> Result<(), syn::Error> {
    if let Some(existing_span) = used_method_names.get(method_name) {
        let mut err = syn::Error::new(
            span,
            format!("Duplicate generated accessor method name `{method_name}` detected"),
        );
        err.combine(syn::Error::new(
            *existing_span,
            "First conflicting field is here",
        ));
        return Err(err);
    }
    used_method_names.insert(method_name.to_string(), span);
    Ok(())
}

fn sanitize_ident_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_ascii_alphanumeric() {
            output.push(c.to_ascii_lowercase());
        } else {
            output.push('_');
        }
    }

    let starts_with_digit = output.chars().next().is_some_and(|c| c.is_ascii_digit());
    if starts_with_digit {
        output.insert(0, '_');
    }

    if output.is_empty() {
        output.push('_');
    }

    output
}

fn process_field(
    field: &Field,
    attrs: &FieldAttrs,
    container_attrs: &ContainerAttrs,
    _cfg_attrs: &[Attribute],
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let Some(field_name) = &field.ident else {
        return Err(syn::Error::new_spanned(
            field,
            "Field must have a name (internal error: expected named field)",
        ));
    };
    let field_type = &field.ty;

    // Check if this is a nested struct.
    // We auto-detect simple structs, but allow explicit `nested`, `flatten` or explicit `object` override.
    let is_structural = match attrs.nesting {
        Nesting::Flatten | Nesting::Nested => true,
        Nesting::Object => false,
        Nesting::Auto => is_nested_struct(field_type),
    };

    if is_structural {
        let prefix = if attrs.nesting == Nesting::Flatten {
            None
        } else {
            Some(field_name.to_string())
        };
        return Ok(generate_nested_field_constructor(field_type, prefix));
    }

    let inner_ty = extract_inner_type_from_option(field_type).unwrap_or(field_type);
    let mut type_info = classify_type(inner_ty);

    // If it's classified as Unknown and we didn't catch it as a nested struct, map it to Object dynamically
    if let TypeInfo::Unknown = type_info {
        type_info = TypeInfo::Object;
    }

    validate_field_type_constraints(field, type_info, attrs)?;

    let category_str = resolve_field_category(attrs, container_attrs);
    let final_field_name = attrs
        .rename
        .clone()
        .unwrap_or_else(|| field_name.to_string());

    let key = if category_str.is_empty() {
        final_field_name.clone()
    } else {
        format!("{category_str}.{final_field_name}")
    };

    let constructor = generate_field_constructor(field_name, field_type, type_info, attrs);
    let modifiers = generate_field_modifiers(attrs);

    Ok(quote! {
        map.insert(
            #key.to_string(),
            { #constructor } #(#modifiers)*
        );
    })
}

fn generate_nested_field_constructor(
    field_type: &syn::Type,
    prefix: Option<String>,
) -> proc_macro2::TokenStream {
    if let Some(p) = prefix {
        quote! {
            // Merge nested struct's metadata with prefix
            // Keys from nested struct are "category.field_name", we extract just "field_name"
            for (key, meta) in <#field_type as rcman::SettingsSchema>::get_metadata() {
                // Extract just the field name (part after last dot)
                let field_only = key.rsplit('.').next().unwrap_or(&key);
                let prefixed_key = format!("{}.{}", #p, field_only);
                // Note: Category is structural (in key), not stored in metadata
                map.insert(prefixed_key, meta);
            }
        }
    } else {
        quote! {
            // Merge nested struct's metadata without prefix (flatten)
            for (key, meta) in <#field_type as rcman::SettingsSchema>::get_metadata() {
                // Extract just the field name
                let field_only = key.rsplit('.').next().unwrap_or(&key);
                map.insert(field_only.to_string(), meta);
            }
        }
    }
}

fn validate_field_type_constraints(
    field: &Field,
    type_info: TypeInfo,
    attrs: &FieldAttrs,
) -> Result<(), syn::Error> {
    // Semantic Compile-Time Validation
    if let (Some(min), Some(max)) = (attrs.min, attrs.max)
        && min > max
    {
        return Err(syn::Error::new_spanned(
            field,
            format!("`min` ({min}) cannot be greater than `max` ({max})"),
        ));
    }

    if let Some(step) = attrs.step
        && step <= 0.0
    {
        return Err(syn::Error::new_spanned(
            field,
            format!("`step` must be positive, got {step}"),
        ));
    }

    match type_info {
        TypeInfo::Number => {
            if attrs.pattern.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`pattern` is only valid for text settings, not numbers",
                ));
            }
        }
        TypeInfo::Text | TypeInfo::Path => {
            if attrs.min.is_some() || attrs.max.is_some() || attrs.step.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`min/max/step` are only valid for numeric settings, not text",
                ));
            }
        }
        TypeInfo::Toggle => {
            if attrs.min.is_some() || attrs.max.is_some() || attrs.step.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`min/max/step` are only valid for numeric settings, not booleans",
                ));
            }
            if attrs.pattern.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`pattern` is only valid for text settings, not booleans",
                ));
            }
            if !attrs.options.is_empty() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`options` are only valid for text/number settings, not booleans",
                ));
            }
        }
        TypeInfo::List => {
            if attrs.min.is_some() || attrs.max.is_some() || attrs.step.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`min/max/step` are only valid for numeric settings, not lists",
                ));
            }
            if attrs.pattern.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`pattern` is only valid for text settings, not lists",
                ));
            }
            if !attrs.options.is_empty() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`options` are only valid for text/number settings, not lists",
                ));
            }
        }
        TypeInfo::Object => {
            if attrs.min.is_some() || attrs.max.is_some() || attrs.step.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`min/max/step` are only valid for numeric settings, not objects",
                ));
            }
            if attrs.pattern.is_some() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`pattern` is only valid for text settings, not objects",
                ));
            }
            if !attrs.options.is_empty() {
                return Err(syn::Error::new_spanned(
                    field,
                    "`options` are only valid for text/number settings, not objects",
                ));
            }
        }
        TypeInfo::Unknown => unreachable!(),
    }
    Ok(())
}

fn resolve_field_category(attrs: &FieldAttrs, container_attrs: &ContainerAttrs) -> String {
    attrs
        .category
        .as_ref()
        .or(container_attrs.category.as_ref())
        .cloned()
        .unwrap_or_default()
}

fn generate_field_constructor(
    field_name: &syn::Ident,
    field_type: &syn::Type,
    type_info: TypeInfo,
    attrs: &FieldAttrs,
) -> proc_macro2::TokenStream {
    if attrs.options.is_empty() {
        generate_setting_type(field_name, field_type, type_info)
    } else {
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
    }
}

fn generate_field_modifiers(attrs: &FieldAttrs) -> Vec<proc_macro2::TokenStream> {
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
        modifiers.push(quote! { .reserved(vec![#(#reserved_items),*]) });
    }

    for (key, value) in &attrs.metadata_str {
        modifiers.push(quote! { .meta_str(#key, #value) });
    }
    for (key, value) in &attrs.metadata_bool {
        modifiers.push(quote! { .meta_bool(#key, #value) });
    }
    for (key, value) in &attrs.metadata_num {
        modifiers.push(quote! { .meta_num(#key, #value) });
    }

    modifiers
}

fn parse_field_attrs(attrs: &[Attribute]) -> Result<FieldAttrs, syn::Error> {
    let mut result = FieldAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("setting") {
            let nested = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;

            for meta in nested {
                parse_single_field_attr(meta, &mut result)?;
            }
        } else if attr.path().is_ident("serde") {
            // Respect serde attributes as fallbacks to reduce boilerplate
            if let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) {
                for meta in nested {
                    match meta {
                        Meta::Path(path) => {
                            if path.is_ident("flatten") {
                                result.nesting = Nesting::Flatten;
                            } else if path.is_ident("skip") {
                                result.skip = true;
                            }
                        }
                        Meta::NameValue(nv) => {
                            if nv.path.is_ident("rename") && result.rename.is_none() {
                                result.rename = parse_lit_str(&nv.value, "rename").ok();
                            }
                        }
                        Meta::List(_) => {}
                    }
                }
            }
        }
    }

    Ok(result)
}

fn parse_single_field_attr(meta: Meta, result: &mut FieldAttrs) -> Result<(), syn::Error> {
    match meta {
        Meta::Path(path) => {
            if path.is_ident("secret") {
                result.secret = true;
            } else if path.is_ident("skip") {
                result.skip = true;
            } else if path.is_ident("nested") {
                result.nesting = Nesting::Nested;
            } else if path.is_ident("object") {
                result.nesting = Nesting::Object;
            } else if path.is_ident("flatten") {
                result.nesting = Nesting::Flatten;
            }
        }
        Meta::NameValue(nv) => {
            let value = &nv.value;
            if nv.path.is_ident("category") {
                result.category = Some(parse_lit_str(value, "category")?);
            } else if nv.path.is_ident("min") {
                result.min = parse_number_constraint(parse_lit_expr(value, "min")?, "min")?;
            } else if nv.path.is_ident("max") {
                result.max = parse_number_constraint(parse_lit_expr(value, "max")?, "max")?;
            } else if nv.path.is_ident("step") {
                result.step = parse_number_constraint(parse_lit_expr(value, "step")?, "step")?;
            } else if nv.path.is_ident("pattern") {
                result.pattern = Some(parse_lit_str(value, "pattern")?);
            } else if nv.path.is_ident("rename") {
                result.rename = Some(parse_lit_str(value, "rename")?);
            } else {
                let key = nv
                    .path
                    .get_ident()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_default();
                let lit = parse_lit_expr(value, &key)?;
                parse_metadata_value(key, lit, result)?;
            }
        }
        Meta::List(list) => {
            if list.path.is_ident("options") {
                parse_options_list(&list, result)?;
            } else if list.path.is_ident("reserved") {
                parse_reserved_list(&list, result)?;
            }
        }
    }
    Ok(())
}

fn parse_lit_str(expr: &syn::Expr, name: &str) -> Result<String, syn::Error> {
    if let syn::Expr::Lit(lit) = expr
        && let Lit::Str(s) = &lit.lit
    {
        return Ok(s.value());
    }
    Err(syn::Error::new_spanned(
        expr,
        format!("#[setting({name})] must be a string literal"),
    ))
}

fn parse_lit_expr<'a>(expr: &'a syn::Expr, name: &str) -> Result<&'a syn::ExprLit, syn::Error> {
    if let syn::Expr::Lit(lit) = expr {
        Ok(lit)
    } else {
        Err(syn::Error::new_spanned(
            expr,
            format!("#[setting({name})] must be a literal"),
        ))
    }
}

/// Container-level attributes from #[schema(...)] and #[serde(...)]
#[derive(Default)]
struct ContainerAttrs {
    category: Option<String>,
    serde_tag: Option<String>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum Nesting {
    #[default]
    Auto,
    Flatten,
    Nested,
    Object,
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
    nesting: Nesting,
    rename: Option<String>,
    // Dynamic metadata: any key=value that isn't a known constraint
    metadata_str: Vec<(String, String)>,
    metadata_bool: Vec<(String, bool)>,
    metadata_num: Vec<(String, f64)>,
}

struct VariantAttrs {
    rename: Option<String>,
    label: Option<String>,
}

fn parse_variant_attrs(attrs: &[Attribute]) -> VariantAttrs {
    let mut result = VariantAttrs {
        rename: None,
        label: None,
    };

    for attr in attrs {
        if attr.path().is_ident("serde") {
            if let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            ) {
                for meta in nested {
                    if let Meta::NameValue(nv) = meta
                        && nv.path.is_ident("rename")
                        && let Expr::Lit(lit) = &nv.value
                        && let Lit::Str(s) = &lit.lit
                    {
                        result.rename = Some(s.value());
                    }
                }
            }
        } else if attr.path().is_ident("setting")
            && let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )
        {
            for meta in nested {
                if let Meta::NameValue(nv) = meta {
                    if nv.path.is_ident("rename")
                        && let Expr::Lit(lit) = &nv.value
                        && let Lit::Str(s) = &lit.lit
                    {
                        result.rename = Some(s.value());
                    } else if nv.path.is_ident("label")
                        && let Expr::Lit(lit) = &nv.value
                        && let Lit::Str(s) = &lit.lit
                    {
                        result.label = Some(s.value());
                    }
                }
            }
        }
    }

    result
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}

fn to_title_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push(' ');
        }
        result.push(ch);
    }
    result
}

fn parse_container_attrs(attrs: &[Attribute]) -> Result<ContainerAttrs, syn::Error> {
    let mut result = ContainerAttrs::default();

    for attr in attrs {
        if attr.path().is_ident("schema") {
            let nested = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;

            for meta in nested {
                if let Meta::NameValue(nv) = meta
                    && nv.path.is_ident("category")
                {
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
        } else if attr.path().is_ident("serde")
            && let Ok(nested) = attr.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )
        {
            for meta in nested {
                if let Meta::NameValue(nv) = meta
                    && nv.path.is_ident("tag")
                    && let Expr::Lit(lit) = &nv.value
                    && let Lit::Str(s) = &lit.lit
                {
                    result.serde_tag = Some(s.value());
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
            if let Ok(val) = i.base10_parse::<f64>() {
                result.metadata_num.push((key, val));
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
#[derive(Copy, Clone)]
enum TypeInfo {
    Toggle,  // bool
    Text,    // String
    Path,    // PathBuf
    Number,  // i8, i16, i32, u32, f32, f64, etc.
    List,    // Vec<T>
    Object,  // serde_json::Value
    Unknown, // Everything else (may be nested struct or std type we don't handle)
}

/// Extract the last segment's identifier from a type path, ignoring generics.
/// Example: `std::vec::Vec<String>` -> `Some(Vec)`
fn get_last_path_segment_ident(ty: &Type) -> Option<&syn::Ident> {
    if let Type::Path(path) = ty {
        path.path.segments.last().map(|seg| &seg.ident)
    } else {
        None
    }
}

/// Classify a type for settings schema generation
///
/// Uses a whitelist approach: known primitives/std types are classified,
/// everything else returns Unknown (could be nested struct or unsupported std type).
fn classify_type(ty: &Type) -> TypeInfo {
    if let Some(ident) = get_last_path_segment_ident(ty) {
        let name = ident.to_string();
        match name.as_str() {
            "bool" => return TypeInfo::Toggle,
            "String" => return TypeInfo::Text,
            "PathBuf" => return TypeInfo::Path,
            "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
            | "u128" | "usize" | "f32" | "f64" => return TypeInfo::Number,
            // Check for Vec specifically
            "Vec" => return TypeInfo::List,
            // Check for serde_json::Value
            "Value" => return TypeInfo::Object,
            // Other std types that are NOT nested structs
            "str" | "char" | "OsString" | "CString" | "Duration" | "Instant" | "SystemTime"
            | "Box" | "Rc" | "Arc" | "Cow" | "VecDeque" | "HashMap" | "HashSet" | "BTreeMap"
            | "BTreeSet" | "LinkedList" | "Option" | "Result" => {
                return TypeInfo::Unknown;
            }
            _ => return TypeInfo::Unknown,
        }
    }

    TypeInfo::Unknown
}

/// Extract the inner type from Option<T> if the given type is an Option
fn extract_inner_type_from_option(ty: &Type) -> Option<&Type> {
    if let Type::Path(path) = ty
        && let Some(segment) = path.path.segments.last()
        && segment.ident == "Option"
        && let syn::PathArguments::AngleBracketed(args) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first()
    {
        return Some(inner_ty);
    }
    None
}

/// Check if a type is likely a nested struct (not a primitive)
///
/// This uses a conservative whitelist approach: known primitive/std types
/// return false, everything else is assumed to be a nested struct.
///
/// For edge cases (like `Option<MyStruct>`), use explicit `#[setting(nested)]`.
fn is_nested_struct(ty: &Type) -> bool {
    // If it's an Option<T>, check the inner type T
    if let Some(inner) = extract_inner_type_from_option(ty) {
        return is_nested_struct(inner);
    }

    // Only simple path types with single ident can be nested
    if let Type::Path(path_ty) = ty
        && get_last_path_segment_ident(ty).is_some()
    {
        // Must not have type arguments (like Option<T> or Vec<T>) to be auto-detected as a nested struct
        if path_ty.path.segments.last().unwrap().arguments.is_empty() {
            // Use classify_type: Unknown + simple ident = likely custom struct
            return matches!(classify_type(ty), TypeInfo::Unknown);
        }
    }
    false
}

/// Generate the appropriate `SettingMetadata` constructor based on type
fn generate_setting_type(
    field_name: &syn::Ident,
    ty: &Type,
    type_info: TypeInfo,
) -> proc_macro2::TokenStream {
    let is_option = extract_inner_type_from_option(ty).is_some();

    let mut base = match type_info {
        TypeInfo::Toggle => {
            if is_option {
                quote! { rcman::SettingMetadata::toggle(defaults.#field_name.unwrap_or_default()) }
            } else {
                quote! { rcman::SettingMetadata::toggle(defaults.#field_name) }
            }
        }
        TypeInfo::Text => {
            if is_option {
                quote! { rcman::SettingMetadata::text(defaults.#field_name.clone().unwrap_or_default()) }
            } else {
                quote! { rcman::SettingMetadata::text(defaults.#field_name.clone()) }
            }
        }
        TypeInfo::Path => {
            if is_option {
                quote! {
                    rcman::SettingMetadata::text(
                        defaults.#field_name.as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    )
                    .meta_str("input_type", "path")
                }
            } else {
                quote! {
                    rcman::SettingMetadata::text(
                        defaults.#field_name.to_string_lossy().into_owned()
                    )
                    .meta_str("input_type", "path")
                }
            }
        }
        TypeInfo::Number => {
            if is_option {
                quote! { rcman::SettingMetadata::number(defaults.#field_name.unwrap_or_default() as f64) }
            } else {
                quote! { rcman::SettingMetadata::number(defaults.#field_name as f64) }
            }
        }
        TypeInfo::List => {
            quote! {
                rcman::SettingMetadata::list(
                    &(defaults.#field_name
                        .iter()
                        .map(|it| it.to_string())
                        .collect::<Vec<String>>())[..]
                )
            }
        }
        TypeInfo::Object => {
            quote! { rcman::SettingMetadata::object(rcman::serde_json::json!(&defaults.#field_name)) }
        }
        TypeInfo::Unknown => {
            unreachable!("Unknown types are rejected in process_field")
        }
    };

    if is_option {
        base.extend(quote! { .nullable(true) });
    }

    base
}
