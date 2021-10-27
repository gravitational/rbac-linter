extern crate z3_sys;
use z3_sys::*;

use std::ffi::{CStr, CString};

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

fn main() {
  unsafe {
    check();
  }
}
