extern crate z3_sys;
use z3_sys::*;
use std::ffi::CString;

pub unsafe fn to_z3_symbol(ctx : Z3_context, name : &str) -> Z3_symbol {
  let name = CString::new("ab").unwrap();
  Z3_mk_string_symbol(ctx, name.as_ptr())
}

pub unsafe fn to_z3_str(ctx : Z3_context, name : &str) -> Z3_ast {
  let name = CString::new(name).unwrap();
  Z3_mk_string(ctx, name.as_ptr())
}

pub unsafe fn new_str_const(ctx : Z3_context, name : &str) -> Z3_ast {
  let str_sort = Z3_mk_string_sort(ctx);
  let name = to_z3_symbol(ctx, name);
  Z3_mk_const(ctx, name, str_sort)
}
