use std::fs;
use std::path::Path;
use std::collections::{HashMap, HashSet};
use walkdir::WalkDir;
use syn::{
    visit::{self, Visit}, parse_file, Attribute, Expr, ExprCall, ExprMethodCall, 
    ExprPath, File, Item, ItemFn, ItemStruct, ItemEnum, ItemTrait, ItemImpl, ItemMod, 
    ItemUse, ItemConst, ItemStatic, ItemType, Local, Meta, Pat, PatIdent, Path as SynPath, Type, TypePath
};
use serde::Serialize;
use anyhow::{Context, Result};

#[derive(Serialize, Debug)]
pub struct SerializableAst {
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "@id")]
    id: String,
    path: String,
    relative_path: String,
    file_size: u64,
    last_modified: Option<String>,
    items: Vec<AstItem>,
}

#[derive(Serialize, Debug, Clone)]
pub enum AstItem {
    Function {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        is_async: bool,
        is_unsafe: bool,
        inputs: Vec<String>,
        output: Option<String>,
        generics: Vec<String>,
    },
    Struct {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        fields: Vec<StructField>,
        generics: Vec<String>,
    },
    Enum {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        variants: Vec<String>,
        generics: Vec<String>,
    },
    Trait {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        items: Vec<String>,
        generics: Vec<String>,
    },
    Impl {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        target_type: String,
        trait_name: Option<String>,
        items: Vec<String>,
        generics: Vec<String>,
    },
    Module {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        items: Vec<String>,
    },
    Use {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        path: String,
        visibility: String,
    },
    Const {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        type_name: String,
    },
    Static {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        type_name: String,
        is_mutable: bool,
    },
    TypeAlias {
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        name: String,
        visibility: String,
        target_type: String,
        generics: Vec<String>,
    },
}

#[derive(Serialize, Debug, Clone)]
pub struct StructField {
    name: Option<String>,
    type_name: String,
    visibility: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct EnhancedAstItem {
    #[serde(flatten)]
    pub base: AstItem,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_calls: Option<Vec<FunctionCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_variables: Option<Vec<LocalVariable>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_references: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derives: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macro_invocations: Option<Vec<MacroInvocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_attributes: Option<TestInfo>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FunctionCall {
    pub callee: String,
    pub is_method: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_type: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LocalVariable {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_annotation: Option<String>,
    pub is_mutable: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct MacroInvocation {
    pub name: String,
    pub kind: String, // "function-like", "attribute", "derive"
}

#[derive(Serialize, Debug, Clone)]
pub struct TestInfo {
    pub is_test: bool,
    pub is_benchmark: bool,
    pub test_name: Option<String>,
    pub should_panic: bool,
    pub ignore: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct CrossReference {
    pub from_id: String,
    pub to_id: String,
    pub ref_type: ReferenceType,
}

#[derive(Serialize, Debug, Clone)]
pub enum ReferenceType {
    Import,
    TypeUsage,
    FunctionCall,
    TraitImpl,
    Derive,
    TestOf,
    MacroUse,
}

#[derive(Serialize)]
struct EnhancedSerializableAst {
    #[serde(flatten)]
    base: SerializableAst,
    enhanced_items: Vec<EnhancedAstItem>,
}

#[derive(Serialize)]
struct EnhancedCrateAsts {
    #[serde(rename = "@context")]
    context: serde_json::Value,
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "@id")]
    id: String,
    crate_name: String,
    crate_path: String,
    files: Vec<EnhancedSerializableAst>,
    cross_references: Vec<CrossReference>,
    total_files: usize,
    successfully_parsed: usize,
    failed_files: Vec<String>,
    stats: CrateStats,
}

#[derive(Serialize, Default)]
struct CrateStats {
    total_functions: usize,
    total_structs: usize,
    total_enums: usize,
    total_traits: usize,
    total_impls: usize,
    total_tests: usize,
    total_function_calls: usize,
    total_derives: usize,
    total_macro_uses: usize,
}

pub fn extract_visibility(vis: &syn::Visibility) -> String {
    match vis {
        syn::Visibility::Public(_) => "pub".to_string(),
        syn::Visibility::Restricted(restricted) => {
            format!("pub({})", quote::quote!(#restricted).to_string())
        }
        syn::Visibility::Inherited => "private".to_string(),
    }
}

pub fn extract_generics(generics: &syn::Generics) -> Vec<String> {
    generics.params.iter().map(|param| {
        match param {
            syn::GenericParam::Type(type_param) => type_param.ident.to_string(),
            syn::GenericParam::Lifetime(lifetime_param) => lifetime_param.lifetime.to_string(),
            syn::GenericParam::Const(const_param) => const_param.ident.to_string(),
        }
    }).collect()
}

pub fn extract_type_string(ty: &syn::Type) -> String {
    quote::quote!(#ty).to_string()
}

pub fn process_item(item: &Item, file_path: &str) -> Option<AstItem> {
    match item {
        Item::Fn(ItemFn { sig, vis, .. }) => {
            let name = sig.ident.to_string();
            Some(AstItem::Function {
                type_: "rust:Function".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                is_async: sig.asyncness.is_some(),
                is_unsafe: sig.unsafety.is_some(),
                inputs: sig.inputs.iter().map(|arg| quote::quote!(#arg).to_string()).collect(),
                output: match &sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some(extract_type_string(ty)),
                },
                generics: extract_generics(&sig.generics),
            })
        }
        Item::Struct(ItemStruct { ident, vis, fields, generics, .. }) => {
            let struct_fields = match fields {
                syn::Fields::Named(fields_named) => {
                    fields_named.named.iter().map(|field| StructField {
                        name: field.ident.as_ref().map(|i| i.to_string()),
                        type_name: extract_type_string(&field.ty),
                        visibility: extract_visibility(&field.vis),
                    }).collect()
                }
                syn::Fields::Unnamed(fields_unnamed) => {
                    fields_unnamed.unnamed.iter().enumerate().map(|(i, field)| StructField {
                        name: Some(i.to_string()),
                        type_name: extract_type_string(&field.ty),
                        visibility: extract_visibility(&field.vis),
                    }).collect()
                }
                syn::Fields::Unit => vec![],
            };

            let name = ident.to_string();
            Some(AstItem::Struct {
                type_: "rust:Struct".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                fields: struct_fields,
                generics: extract_generics(generics),
            })
        }
        Item::Enum(ItemEnum { ident, vis, variants, generics, .. }) => {
            let name = ident.to_string();
            Some(AstItem::Enum {
                type_: "rust:Enum".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                variants: variants.iter().map(|v| v.ident.to_string()).collect(),
                generics: extract_generics(generics),
            })
        }
        Item::Trait(ItemTrait { ident, vis, items, generics, .. }) => {
            let name = ident.to_string();
            Some(AstItem::Trait {
                type_: "rust:Trait".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                items: items.iter().map(|item| quote::quote!(#item).to_string()).collect(),
                generics: extract_generics(generics),
            })
        }
        Item::Impl(ItemImpl { self_ty, trait_, items, generics, .. }) => {
            let target_type = extract_type_string(self_ty);
            let impl_id = match trait_ {
                Some((_, path, _)) => format!("{}#impl_{}_{}", file_path, quote::quote!(#path).to_string().replace(" ", ""), target_type.replace(" ", "")),
                None => format!("{}#impl_{}", file_path, target_type.replace(" ", "")),
            };
            Some(AstItem::Impl {
                type_: "rust:Impl".to_string(),
                id: impl_id,
                target_type,
                trait_name: trait_.as_ref().map(|(_, path, _)| quote::quote!(#path).to_string()),
                items: items.iter().map(|item| quote::quote!(#item).to_string()).collect(),
                generics: extract_generics(generics),
            })
        }
        Item::Mod(ItemMod { ident, vis, content, .. }) => {
            let items = if let Some((_, items)) = content {
                items.iter().map(|item| quote::quote!(#item).to_string()).collect()
            } else {
                vec![]
            };

            let name = ident.to_string();
            Some(AstItem::Module {
                type_: "rust:Module".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                items,
            })
        }
        Item::Use(ItemUse { tree, vis, .. }) => {
            let path_str = quote::quote!(#tree).to_string();
            Some(AstItem::Use {
                type_: "rust:Use".to_string(),
                id: format!("{}#use_{}", file_path, path_str.replace(" ", "").replace("::", "_")),
                path: path_str,
                visibility: extract_visibility(vis),
            })
        }
        Item::Const(ItemConst { ident, vis, ty, .. }) => {
            let name = ident.to_string();
            Some(AstItem::Const {
                type_: "rust:Const".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                type_name: extract_type_string(ty),
            })
        }
        Item::Static(ItemStatic { ident, vis, ty, mutability, .. }) => {
            let name = ident.to_string();
            Some(AstItem::Static {
                type_: "rust:Static".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                type_name: extract_type_string(ty),
                is_mutable: matches!(mutability, syn::StaticMutability::Mut(_)),
            })
        }
        Item::Type(ItemType { ident, vis, ty, generics, .. }) => {
            let name = ident.to_string();
            Some(AstItem::TypeAlias {
                type_: "rust:TypeAlias".to_string(),
                id: format!("{}#{}", file_path, name),
                name,
                visibility: extract_visibility(vis),
                target_type: extract_type_string(ty),
                generics: extract_generics(generics),
            })
        }
        _ => None, // Skip other item types for now
    }
}

pub fn extract_crate_info(file_path: &Path) -> Option<(String, String)> {
    let path_str = file_path.to_string_lossy();

    // Look for crates/ directory pattern
    if let Some(crates_pos) = path_str.find("crates/") {
        let after_crates = &path_str[crates_pos + 7..]; // Skip "crates/"

        // Handle nested crates like node_types/prover
        let parts: Vec<&str> = after_crates.split('/').collect();
        if parts.len() >= 2 {
            if parts[0] == "node_types" || parts[0] == "zk" {
                // For nested crates like node_types/prover or zk/sp1
                let crate_name = format!("{}_{}", parts[0], parts[1]);
                let crate_path = format!("crates/{}/{}", parts[0], parts[1]);
                return Some((crate_name, crate_path));
            } else {
                // For regular crates like common, storage, etc.
                let crate_name = parts[0].to_string();
                let crate_path = format!("crates/{}", parts[0]);
                return Some((crate_name, crate_path));
            }
        }
    }

    // Handle root-level files (like benches)
    if path_str.contains("benches/") {
        return Some(("benches".to_string(), "benches".to_string()));
    }

    None
}

/// Enhanced AST extractor that analyzes function bodies and collects additional relationships
pub struct EnhancedAstExtractor {
    pub items: Vec<EnhancedAstItem>,
    pub cross_references: Vec<CrossReference>,
    current_item_id: String,
    file_path: String,
}

impl EnhancedAstExtractor {
    pub fn new(file_path: String) -> Self {
        Self {
            items: Vec::new(),
            cross_references: Vec::new(),
            current_item_id: String::new(),
            file_path,
        }
    }

    pub fn extract_from_file(&mut self, ast: &File) -> Result<()> {
        for item in &ast.items {
            self.process_item(item);
        }
        Ok(())
    }

    fn process_item(&mut self, item: &Item) {
        let base_item = process_item(item, &self.file_path);
        if let Some(base) = base_item {
            let mut enhanced = EnhancedAstItem {
                base: base.clone(),
                function_calls: None,
                local_variables: None,
                type_references: None,
                derives: None,
                macro_invocations: None,
                test_attributes: None,
            };

            // Extract item-specific enhancements
            match item {
                Item::Fn(item_fn) => {
                    self.enhance_function(&mut enhanced, item_fn);
                }
                Item::Struct(item_struct) => {
                    self.enhance_struct(&mut enhanced, item_struct);
                }
                Item::Enum(item_enum) => {
                    self.enhance_enum(&mut enhanced, item_enum);
                }
                Item::Impl(item_impl) => {
                    self.enhance_impl(&mut enhanced, item_impl);
                }
                Item::Use(item_use) => {
                    self.enhance_use(&mut enhanced, item_use);
                }
                _ => {}
            }

            self.items.push(enhanced);
        }
    }

    fn enhance_function(&mut self, enhanced: &mut EnhancedAstItem, item_fn: &ItemFn) {
        // Extract test attributes
        enhanced.test_attributes = self.extract_test_attributes(&item_fn.attrs);

        // Create a function body visitor
        let mut visitor = FunctionBodyVisitor::new();
        visitor.visit_block(&item_fn.block);

        // Generate cross-references for function calls
        if let AstItem::Function { id, .. } = &enhanced.base {
            self.current_item_id = id.clone();
            for call in visitor.function_calls.iter() {
                self.cross_references.push(CrossReference {
                    from_id: id.clone(),
                    to_id: call.callee.clone(),
                    ref_type: ReferenceType::FunctionCall,
                });
            }
        }
        
        enhanced.function_calls = Some(visitor.function_calls);
        enhanced.local_variables = Some(visitor.local_variables);
        enhanced.type_references = Some(visitor.type_references.into_iter().collect());
        enhanced.macro_invocations = Some(visitor.macro_invocations);
    }

    fn enhance_struct(&mut self, enhanced: &mut EnhancedAstItem, item_struct: &ItemStruct) {
        enhanced.derives = self.extract_derives(&item_struct.attrs);
        
        // Add cross-references for derives
        if let (AstItem::Struct { id, .. }, Some(derives)) = (&enhanced.base, &enhanced.derives) {
            for derive in derives {
                self.cross_references.push(CrossReference {
                    from_id: id.clone(),
                    to_id: format!("trait:{}", derive),
                    ref_type: ReferenceType::Derive,
                });
            }
        }
    }

    fn enhance_enum(&mut self, enhanced: &mut EnhancedAstItem, item_enum: &ItemEnum) {
        enhanced.derives = self.extract_derives(&item_enum.attrs);
        
        // Add cross-references for derives
        if let (AstItem::Enum { id, .. }, Some(derives)) = (&enhanced.base, &enhanced.derives) {
            for derive in derives {
                self.cross_references.push(CrossReference {
                    from_id: id.clone(),
                    to_id: format!("trait:{}", derive),
                    ref_type: ReferenceType::Derive,
                });
            }
        }
    }

    fn enhance_impl(&mut self, enhanced: &mut EnhancedAstItem, item_impl: &ItemImpl) {
        // Extract type references from the impl block
        let mut type_refs = HashSet::new();
        let mut type_visitor = TypeReferenceVisitor::new(&mut type_refs);
        type_visitor.visit_type(&item_impl.self_ty);
        
        enhanced.type_references = Some(type_refs.into_iter().collect());

        // Add cross-reference for trait implementation
        if let (AstItem::Impl { id, target_type: _, trait_name: _, .. }, Some(trait_name_str)) = 
            (&enhanced.base, &item_impl.trait_.as_ref().map(|(_, path, _)| path_to_string(path))) {
            self.cross_references.push(CrossReference {
                from_id: id.clone(),
                to_id: format!("trait:{}", trait_name_str),
                ref_type: ReferenceType::TraitImpl,
            });
        }
    }

    fn enhance_use(&mut self, enhanced: &mut EnhancedAstItem, _item_use: &ItemUse) {
        // Add cross-reference for imports
        if let AstItem::Use { path, .. } = &enhanced.base {
            self.cross_references.push(CrossReference {
                from_id: self.file_path.clone(),
                to_id: path.clone(),
                ref_type: ReferenceType::Import,
            });
        }
    }

    fn extract_derives(&self, attrs: &[Attribute]) -> Option<Vec<String>> {
        let mut derives = Vec::new();
        
        for attr in attrs {
            if attr.path().is_ident("derive") {
                if let Meta::List(meta_list) = &attr.meta {
                    meta_list.tokens.clone().into_iter().for_each(|token| {
                        if let proc_macro2::TokenTree::Ident(ident) = token {
                            derives.push(ident.to_string());
                        }
                    });
                }
            }
        }
        
        if derives.is_empty() {
            None
        } else {
            Some(derives)
        }
    }

    fn extract_test_attributes(&self, attrs: &[Attribute]) -> Option<TestInfo> {
        let mut test_info = TestInfo {
            is_test: false,
            is_benchmark: false,
            test_name: None,
            should_panic: false,
            ignore: false,
        };

        for attr in attrs {
            if attr.path().is_ident("test") {
                test_info.is_test = true;
            } else if attr.path().is_ident("bench") {
                test_info.is_benchmark = true;
            } else if attr.path().is_ident("should_panic") {
                test_info.should_panic = true;
            } else if attr.path().is_ident("ignore") {
                test_info.ignore = true;
            }
        }

        if test_info.is_test || test_info.is_benchmark {
            Some(test_info)
        } else {
            None
        }
    }
}

/// Visitor for analyzing function bodies
struct FunctionBodyVisitor {
    function_calls: Vec<FunctionCall>,
    local_variables: Vec<LocalVariable>,
    type_references: HashSet<String>,
    macro_invocations: Vec<MacroInvocation>,
}

impl FunctionBodyVisitor {
    fn new() -> Self {
        Self {
            function_calls: Vec::new(),
            local_variables: Vec::new(),
            type_references: HashSet::new(),
            macro_invocations: Vec::new(),
        }
    }
}

impl<'ast> Visit<'ast> for FunctionBodyVisitor {
    fn visit_expr_call(&mut self, expr: &'ast ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*expr.func {
            self.function_calls.push(FunctionCall {
                callee: path_to_string(path),
                is_method: false,
                receiver_type: None,
            });
        }
        visit::visit_expr_call(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast ExprMethodCall) {
        let receiver_type = match &*expr.receiver {
            Expr::Path(ExprPath { path, .. }) => Some(path_to_string(path)),
            _ => None,
        };

        self.function_calls.push(FunctionCall {
            callee: expr.method.to_string(),
            is_method: true,
            receiver_type,
        });
        
        visit::visit_expr_method_call(self, expr);
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Pat::Ident(PatIdent { ident, mutability, .. }) = &local.pat {
            let type_annotation = if let Pat::Type(pat_type) = &local.pat {
                Some(quote::quote!(#pat_type.ty).to_string())
            } else {
                None
            };

            self.local_variables.push(LocalVariable {
                name: ident.to_string(),
                type_annotation,
                is_mutable: mutability.is_some(),
            });
        }
        
        visit::visit_local(self, local);
    }

    fn visit_type(&mut self, ty: &'ast Type) {
        if let Type::Path(TypePath { path, .. }) = ty {
            self.type_references.insert(path_to_string(path));
        }
        visit::visit_type(self, ty);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(ident) = mac.path.get_ident() {
            self.macro_invocations.push(MacroInvocation {
                name: ident.to_string(),
                kind: "function-like".to_string(),
            });
        }
        visit::visit_macro(self, mac);
    }
}

/// Visitor for extracting type references
struct TypeReferenceVisitor<'a> {
    type_references: &'a mut HashSet<String>,
}

impl<'a> TypeReferenceVisitor<'a> {
    fn new(type_references: &'a mut HashSet<String>) -> Self {
        Self { type_references }
    }
}

impl<'ast, 'a> Visit<'ast> for TypeReferenceVisitor<'a> {
    fn visit_type(&mut self, ty: &'ast Type) {
        if let Type::Path(TypePath { path, .. }) = ty {
            self.type_references.insert(path_to_string(path));
        }
        visit::visit_type(self, ty);
    }
}

/// Helper function to convert a Path to a string
fn path_to_string(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Second-pass analyzer for resolving cross-references
pub struct CrossReferenceResolver {
    /// Map from item names to their full IDs
    item_index: HashMap<String, Vec<String>>,
    /// Map from module paths to their IDs
    module_index: HashMap<String, String>,
}

impl CrossReferenceResolver {
    pub fn new() -> Self {
        Self {
            item_index: HashMap::new(),
            module_index: HashMap::new(),
        }
    }

    /// Build indices from all parsed items
    pub fn build_indices(&mut self, all_items: &[(String, Vec<EnhancedAstItem>)]) {
        for (crate_name, items) in all_items {
            for item in items {
                self.index_item(crate_name, &item.base);
            }
        }
    }

    fn index_item(&mut self, _crate_name: &str, item: &AstItem) {
        match item {
            AstItem::Function { id, name, .. } |
            AstItem::Struct { id, name, .. } |
            AstItem::Enum { id, name, .. } |
            AstItem::Trait { id, name, .. } |
            AstItem::Const { id, name, .. } |
            AstItem::Static { id, name, .. } |
            AstItem::TypeAlias { id, name, .. } => {
                self.item_index.entry(name.clone())
                    .or_insert_with(Vec::new)
                    .push(id.clone());
            }
            AstItem::Module { id, name, .. } => {
                self.module_index.insert(name.clone(), id.clone());
            }
            _ => {}
        }
    }

    /// Resolve a reference to its target ID
    pub fn resolve_reference(&self, reference: &str, context_crate: &str) -> Option<String> {
        // Try direct lookup
        if let Some(ids) = self.item_index.get(reference) {
            // Prefer items from the same crate
            for id in ids {
                if id.contains(context_crate) {
                    return Some(id.clone());
                }
            }
            // Otherwise return the first match
            return ids.first().cloned();
        }

        // Try module path resolution
        let parts: Vec<&str> = reference.split("::").collect();
        if parts.len() > 1 {
            // Check if it's a module path
            if let Some(module_id) = self.module_index.get(parts[0]) {
                // Try to find the item in that module
                let item_name = parts.last().unwrap();
                if let Some(ids) = self.item_index.get(*item_name) {
                    for id in ids {
                        if id.contains(module_id) {
                            return Some(id.clone());
                        }
                    }
                }
            }
        }

        None
    }

    /// Enhance cross-references with resolved IDs
    pub fn resolve_cross_references(&self, 
        cross_refs: &mut Vec<CrossReference>, 
        context_crate: &str
    ) {
        for cross_ref in cross_refs.iter_mut() {
            if let Some(resolved_id) = self.resolve_reference(&cross_ref.to_id, context_crate) {
                cross_ref.to_id = resolved_id;
            }
        }
    }
}

pub fn run_ast_parser() -> Result<()> {
    println!("Starting AST parsing of the codebase...");

    let root = "../";
    let mut crates_data: HashMap<String, (String, Vec<EnhancedSerializableAst>, Vec<CrossReference>, Vec<String>)> = HashMap::new();
    let mut total_files = 0;

    // First pass: Parse all files and collect enhanced AST data
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            let path = e.path();
            path.extension().map_or(false, |ext| ext == "rs") &&
            !path.to_string_lossy().contains("/target/") &&
            !path.to_string_lossy().contains("/ast_parser/")
        })
    {
        let path = entry.path();
        total_files += 1;

        let (crate_name, crate_path) = match extract_crate_info(path) {
            Some(info) => info,
            None => {
                println!("Skipping file outside known crate structure: {}", path.display());
                continue;
            }
        };

        println!("Parsing [{}]: {}", crate_name, path.display());

        let code = match fs::read_to_string(path) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Failed to read {}: {}", path.display(), e);
                let entry = crates_data.entry(crate_name).or_insert((crate_path, Vec::new(), Vec::new(), Vec::new()));
                entry.3.push(format!("{}: read error - {}", path.display(), e));
                continue;
            }
        };

        match parse_file(&code) {
            Ok(ast) => {
                let relative_path = path.strip_prefix("../").unwrap_or(path).display().to_string();
                
                // Use enhanced extractor
                let mut extractor = EnhancedAstExtractor::new(relative_path.clone());
                if let Err(e) = extractor.extract_from_file(&ast) {
                    eprintln!("Failed to extract enhanced AST from {}: {}", path.display(), e);
                    continue;
                }

                // Also get basic items for the base structure
                let basic_items: Vec<AstItem> = ast.items.iter()
                    .filter_map(|item| process_item(item, &relative_path))
                    .collect();

                // Get file metadata
                let metadata = fs::metadata(path).ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let last_modified = metadata.and_then(|m| {
                    m.modified().ok().and_then(|time| {
                        time.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|duration| {
                                let secs = duration.as_secs();
                                chrono::DateTime::from_timestamp(secs as i64, 0)
                                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            })
                            .flatten()
                    })
                });

                let base_ast = SerializableAst {
                    type_: "rust:SourceFile".to_string(),
                    id: relative_path.clone(),
                    path: path.display().to_string(),
                    relative_path,
                    file_size,
                    last_modified,
                    items: basic_items,
                };

                let enhanced_ast = EnhancedSerializableAst {
                    base: base_ast,
                    enhanced_items: extractor.items,
                };

                let entry = crates_data.entry(crate_name.clone()).or_insert((crate_path, Vec::new(), Vec::new(), Vec::new()));
                entry.1.push(enhanced_ast);
                entry.2.extend(extractor.cross_references);

                println!("✓ Successfully parsed [{}]: {}", crate_name, path.display());
            }
            Err(e) => {
                eprintln!("Failed to parse {}: {}", path.display(), e);
                let entry = crates_data.entry(crate_name).or_insert((crate_path, Vec::new(), Vec::new(), Vec::new()));
                entry.3.push(format!("{}: parse error - {}", path.display(), e));
            }
        }
    }

    println!("\nFirst pass complete! Starting cross-reference resolution...");

    // Second pass: Resolve cross-references
    let mut resolver = CrossReferenceResolver::new();
    
    // Build indices from all items
    let all_items: Vec<(String, Vec<EnhancedAstItem>)> = crates_data.iter()
        .map(|(crate_name, (_, files, _, _))| {
            let items: Vec<EnhancedAstItem> = files.iter()
                .flat_map(|file| file.enhanced_items.clone())
                .collect();
            (crate_name.clone(), items)
        })
        .collect();
    
    resolver.build_indices(&all_items);

    // Resolve cross-references for each crate
    for (crate_name, (_, _, cross_refs, _)) in crates_data.iter_mut() {
        resolver.resolve_cross_references(cross_refs, crate_name);
    }

    println!("Cross-reference resolution complete!");

    // Create output directory
    let output_dir = "../ast_output";
    fs::create_dir_all(output_dir).context("Failed to create output directory")?;

    let mut total_successfully_parsed = 0;
    let mut total_failed = 0;
    
    // First, generate the graph file while we still own crates_data
    generate_graph_file(&output_dir, &crates_data)?;

    // Generate enhanced AST files for each crate
    for (crate_name, (crate_path, files, cross_refs, failed_files)) in crates_data {
        // Calculate statistics
        let mut stats = CrateStats::default();
        
        for file in &files {
            for item in &file.enhanced_items {
                match &item.base {
                    AstItem::Function { .. } => {
                        stats.total_functions += 1;
                        if let Some(test_info) = &item.test_attributes {
                            if test_info.is_test {
                                stats.total_tests += 1;
                            }
                        }
                        if let Some(calls) = &item.function_calls {
                            stats.total_function_calls += calls.len();
                        }
                    }
                    AstItem::Struct { .. } => {
                        stats.total_structs += 1;
                        if let Some(derives) = &item.derives {
                            stats.total_derives += derives.len();
                        }
                    }
                    AstItem::Enum { .. } => {
                        stats.total_enums += 1;
                        if let Some(derives) = &item.derives {
                            stats.total_derives += derives.len();
                        }
                    }
                    AstItem::Trait { .. } => stats.total_traits += 1,
                    AstItem::Impl { .. } => stats.total_impls += 1,
                    _ => {}
                }
                
                if let Some(macros) = &item.macro_invocations {
                    stats.total_macro_uses += macros.len();
                }
            }
        }

        // Enhanced context with proper JSON-LD semantic mappings
        let context = serde_json::json!({
            "@version": 1.1,
            "@vocab": "https://schema.org/",
            "rust": "https://w3id.org/rust/vocab#",
            "crate": "https://w3id.org/rust/crate/",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
            "dcterms": "http://purl.org/dc/terms/",
            
            "crate_name": "name",
            "crate_path": "rust:cratePath",
            "cross_references": "rust:crossReferences",
            "derives": "rust:derives",
            "failed_files": "rust:failedFiles",
            "file_size": "contentSize",
            "files": "hasPart",
            "function_calls": "rust:functionCalls",
            "items": "hasPart",
            "last_modified": "dateModified",
            "local_variables": "rust:localVariables",
            "macro_invocations": "rust:macroInvocations",
            "name": "name",
            "path": "rust:path",
            "relative_path": "rust:relativePath",
            "stats": "rust:statistics",
            "successfully_parsed": "rust:successfullyParsed",
            "test_attributes": "rust:testAttributes",
            "total_files": "rust:totalFiles",
            "type_references": "rust:typeReferences",
            "visibility": "rust:visibility",
            "generics": "rust:generics",
            "fields": "rust:fields",
            "variants": "rust:variants",
            "target_type": "rust:targetType",
            "trait_name": "rust:traitName",
            "attributes": "rust:attributes",
            "label": "rdfs:label",
            "edge_type": "rust:edgeType",
            "edges": "rust:edges",
            "nodes": "hasPart",
            "source": "rust:source",
            "target": "rust:target"
        });

        let enhanced_crate_asts = EnhancedCrateAsts {
            context,
            type_: "rust:Crate".to_string(),
            id: format!("crate:{}", crate_name),
            crate_name: crate_name.clone(),
            crate_path,
            successfully_parsed: files.len(),
            total_files: files.len() + failed_files.len(),
            files,
            cross_references: cross_refs,
            failed_files,
            stats,
        };

        total_successfully_parsed += enhanced_crate_asts.successfully_parsed;
        total_failed += enhanced_crate_asts.failed_files.len();

        println!("\nCrate [{}]:", crate_name);
        println!("  Successfully parsed: {}", enhanced_crate_asts.successfully_parsed);
        println!("  Failed to parse: {}", enhanced_crate_asts.failed_files.len());
        println!("  Statistics:");
        println!("    Functions: {} (Tests: {})", enhanced_crate_asts.stats.total_functions, enhanced_crate_asts.stats.total_tests);
        println!("    Structs: {}", enhanced_crate_asts.stats.total_structs);
        println!("    Enums: {}", enhanced_crate_asts.stats.total_enums);
        println!("    Traits: {}", enhanced_crate_asts.stats.total_traits);
        println!("    Impls: {}", enhanced_crate_asts.stats.total_impls);
        println!("    Function calls tracked: {}", enhanced_crate_asts.stats.total_function_calls);
        println!("    Derives used: {}", enhanced_crate_asts.stats.total_derives);
        println!("    Macro invocations: {}", enhanced_crate_asts.stats.total_macro_uses);
        println!("    Cross-references: {}", enhanced_crate_asts.cross_references.len());

        if !enhanced_crate_asts.failed_files.is_empty() {
            println!("  Failed files:");
            for failed in &enhanced_crate_asts.failed_files {
                println!("    - {}", failed);
            }
        }

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&enhanced_crate_asts)
            .context("Failed to serialize enhanced crate ASTs to JSON")?;

        let output_path = format!("{}/{}_ast.jsonld", output_dir, crate_name);
        fs::write(&output_path, json)
            .context("Failed to write enhanced crate AST JSON-LD file")?;

        println!("  ✓ ASTs saved to: {}", output_path);
        println!("  File size: {} bytes", fs::metadata(&output_path)?.len());
    }

    println!("\n=== AST PARSER SUMMARY ===");
    println!("Total files processed: {}", total_files);
    println!("Successfully parsed: {}", total_successfully_parsed);
    println!("Failed to parse: {}", total_failed);
    println!("JSON-LD AST files with knowledge graph generated in: {}", output_dir);

    Ok(())
}

fn generate_graph_file(output_dir: &str, crates_data: &HashMap<String, (String, Vec<EnhancedSerializableAst>, Vec<CrossReference>, Vec<String>)>) -> Result<()> {
    #[derive(Serialize)]
    struct KnowledgeGraph {
        #[serde(rename = "@context")]
        context: serde_json::Value,
        #[serde(rename = "@type")]
        type_: String,
        #[serde(rename = "@id")]
        id: String,
        nodes: Vec<GraphNode>,
        edges: Vec<GraphEdge>,
    }

    #[derive(Serialize)]
    struct GraphNode {
        #[serde(rename = "@id")]
        id: String,
        #[serde(rename = "@type")]
        type_: String,
        label: String,
        crate_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        attributes: Option<serde_json::Value>,
    }

    #[derive(Serialize)]
    struct GraphEdge {
        #[serde(rename = "@id")]
        id: String,
        source: String,
        target: String,
        edge_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        weight: Option<f32>,
    }

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut edge_counter = 0;

    // Collect all nodes
    for (crate_name, (_, files, _, _)) in crates_data {
        for file in files {
            for item in &file.enhanced_items {
                let (node_id, node_type, label) = match &item.base {
                    AstItem::Function { id, name, .. } => (id.clone(), "Function", name.clone()),
                    AstItem::Struct { id, name, .. } => (id.clone(), "Struct", name.clone()),
                    AstItem::Enum { id, name, .. } => (id.clone(), "Enum", name.clone()),
                    AstItem::Trait { id, name, .. } => (id.clone(), "Trait", name.clone()),
                    AstItem::Module { id, name, .. } => (id.clone(), "Module", name.clone()),
                    _ => continue,
                };

                let mut attributes = serde_json::Map::new();
                
                // Add test information
                if let Some(test_info) = &item.test_attributes {
                    attributes.insert("is_test".to_string(), serde_json::Value::Bool(test_info.is_test));
                    attributes.insert("is_benchmark".to_string(), serde_json::Value::Bool(test_info.is_benchmark));
                }
                
                // Add derive information
                if let Some(derives) = &item.derives {
                    attributes.insert("derives".to_string(), serde_json::json!(derives));
                }

                nodes.push(GraphNode {
                    id: node_id,
                    type_: format!("rust:{}", node_type),
                    label,
                    crate_name: crate_name.clone(),
                    attributes: if attributes.is_empty() { None } else { Some(serde_json::Value::Object(attributes)) },
                });
            }
        }
    }

    // Collect all edges
    for (_, (_, _, cross_refs, _)) in crates_data {
        for cross_ref in cross_refs {
            edge_counter += 1;
            edges.push(GraphEdge {
                id: format!("edge_{}", edge_counter),
                source: cross_ref.from_id.clone(),
                target: cross_ref.to_id.clone(),
                edge_type: format!("{:?}", cross_ref.ref_type),
                weight: None,
            });
        }
    }

    let graph = KnowledgeGraph {
        context: serde_json::json!({
            "@version": 1.1,
            "@vocab": "https://schema.org/",
            "rust": "https://w3id.org/rust/vocab#",
            "crate": "https://w3id.org/rust/crate/",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
            "dcterms": "http://purl.org/dc/terms/",
            "nodes": "hasPart",
            "edges": "rust:edges",
            "source": "rust:source",
            "target": "rust:target",
            "edge_type": "rust:edgeType",
            "label": "rdfs:label"
        }),
        type_: "KnowledgeGraph".to_string(),
        id: "rust_project_knowledge_graph".to_string(),
        nodes,
        edges,
    };

    let json = serde_json::to_string_pretty(&graph)?;
    let output_path = format!("{}/knowledge_graph.jsonld", output_dir);
    fs::write(&output_path, json)?;

    println!("\n✓ Knowledge graph saved to: {}", output_path);
    println!("  Total nodes: {}", graph.nodes.len());
    println!("  Total edges: {}", graph.edges.len());

    Ok(())
}

fn main() -> Result<()> {
    run_ast_parser()
}