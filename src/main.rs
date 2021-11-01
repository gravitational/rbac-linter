extern crate z3_sys;
extern crate serde;
extern crate serde_yaml;
mod helpers;

use helpers::*;
use std::env;
use std::ffi::{CStr, CString};
use std::collections::HashMap;
use serde::Deserialize;
use z3_sys::*;

unsafe fn check() {
  let cfg = Z3_mk_config();
  let ctx = Z3_mk_context(cfg);
  let slvr = Z3_mk_solver(ctx);
  let str_sort = Z3_mk_string_sort(ctx);
  let int_sort = Z3_mk_int_sort(ctx);

  let x_str = CString::new("x").unwrap();
  let x_symbol = Z3_mk_string_symbol(ctx, x_str.as_ptr());
  let const_x = Z3_mk_const(ctx, x_symbol, str_sort);

  /*
  let y_str = CString::new("bar").unwrap();
  let y = Z3_mk_string(ctx, y_str.as_ptr());

  let z_str = CString::new("foo").unwrap();
  let z = Z3_mk_string(ctx, z_str.as_ptr());

  let p = Z3_mk_seq_prefix(ctx, z, const_x);
  let s = Z3_mk_seq_suffix(ctx, y, const_x);
  Z3_solver_assert(ctx, slvr, p);
  Z3_solver_assert(ctx, slvr, s);
  */
  
  // Asserts x matches regex ab*
  let ab_str = CString::new("ab").unwrap();
  let ab_ast = Z3_mk_string(ctx, ab_str.as_ptr());
  let ab_re = Z3_mk_seq_to_re(ctx, ab_ast);
  let re = Z3_mk_re_star(ctx, ab_re);
  let matches = Z3_mk_seq_in_re(ctx, const_x, re);
  Z3_solver_assert(ctx, slvr, matches);
  
  // Asserts x must be of length 6
  let x_len = Z3_mk_seq_length(ctx, const_x);
  let six = Z3_mk_int(ctx, 6, int_sort);
  let eq_six = Z3_mk_eq(ctx, x_len, six);
  Z3_solver_assert(ctx, slvr, eq_six);

  let result = Z3_solver_check(ctx, slvr);
  println!("{:?}", result);
  let model = Z3_solver_get_model(ctx, slvr);
  let p = Z3_model_to_string(ctx, model);
  let s = CStr::from_ptr(p).to_str().unwrap();
  println!("{:?}", s);
  Z3_del_context(ctx);
}

#[derive(Debug, Deserialize)]
#[serde(untagged)] 
enum Constraint {
  Single(String),
  Multiple(Vec<String>)
}

#[derive(Debug, Deserialize)]
struct RoleTemplateRules {
  node_labels : HashMap<String, Constraint>
}

#[derive(Debug, Deserialize)]
struct RoleTemplateSpec {
  allow : Option<RoleTemplateRules>,
  deny  : Option<RoleTemplateRules>
}

#[derive(Debug, Deserialize)]
struct RoleTemplateMetadata {
  name : String
}

#[derive(Debug, Deserialize)]
struct RoleTemplate {
  kind      : String,
  version   : String,
  metadata  : RoleTemplateMetadata,
  spec      : RoleTemplateSpec
}

impl RoleTemplate {
  unsafe fn is_allowed(&self, ctx : Z3_context) {
    let str_sort = Z3_mk_string_sort(ctx);
    let kv_tuple = to_z3_symbol(ctx, "key_value_tuple");
    let key_field = to_z3_symbol(ctx, "key");
    let value_field = to_z3_symbol(ctx, "value");
    let field_names = [key_field, value_field];
    let field_sorts = [str_sort, str_sort];
    let mut constructor = 0 as *mut _Z3_func_decl;
    let mut projectors = 0 as Z3_func_decl;
    println!("{:p}", constructor);
    println!("{:p}", projectors);
    let tuple_sort = 
      Z3_mk_tuple_sort(
        ctx,
        kv_tuple,
        2,
        field_names.as_ptr(),
        field_sorts.as_ptr(),
        &mut constructor,
        &mut projectors
      );
    
    println!("{:p}", constructor);
    println!("{:p}", projectors);
    let expected_key = to_z3_str(ctx, "env");
    let expected_value = to_z3_str(ctx, "test");
    let expected_kv = [expected_key, expected_value];
    let expected_tuple = Z3_mk_app(ctx, constructor, 2, expected_kv.as_ptr());
    
    let actual_key = new_str_const(ctx, "k");
    let actual_value = new_str_const(ctx, "v");
    let actual_kv = [actual_key, actual_value];
    let actual_tuple = Z3_mk_app(ctx, constructor, 2, actual_kv.as_ptr());
    
    let eq = Z3_mk_eq(ctx, expected_tuple, actual_tuple);
    
    let slvr = Z3_mk_solver(ctx);
    //Z3_solver_assert(ctx, slvr, eq);
    let result = Z3_solver_check(ctx, slvr);
    println!("{:?}", result);
    let model = Z3_solver_get_model(ctx, slvr);
    let p = Z3_model_to_string(ctx, model);
    let s = CStr::from_ptr(p).to_str().unwrap();
    println!("{:?}", s);
    Z3_del_context(ctx);
    println!("Somehow haven't blown up");
  }

  fn equivalent_to(&self, other : RoleTemplate) -> bool {
    unsafe {
      let cfg = Z3_mk_config();
      let ctx = Z3_mk_context(cfg);
      let slvr = Z3_mk_solver(ctx);
    }

    return false;
  }
}

fn test(rt : RoleTemplate) {
    unsafe {
      let cfg = Z3_mk_config();
      let ctx = Z3_mk_context(cfg);
      rt.is_allowed(ctx);
    }
}

fn main() {
  let args: Vec<String> = env::args().collect();
  let role_template_path = &args[1];
  println!("Parsing role template {}", role_template_path);
  let role_template_file =
    std::fs::read_to_string(role_template_path)
      .expect("Error opening role template file");
  let role_template : RoleTemplate =
    serde_yaml::from_str(&role_template_file)
      .expect("Error parsing YAML in role template file");
  test(role_template);
}
