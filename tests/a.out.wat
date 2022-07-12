(module
  (type $t0 (func (result i32)))
  (type $t1 (func (param i32)))
  (type $t2 (func))
  (type $t3 (func (param i32) (result i32)))
  (type $t4 (func (param i32 i32 i32) (result i32)))
  (type $t5 (func (param i32 i32)))
  (type $t6 (func (param i32 i32) (result i32)))
  (type $t7 (func (param i32 i64 i32) (result i64)))
  (func $__wasm_call_ctors (type $t2)
    call $emscripten_stack_init)
  (func $f1 (type $t4) (param $p0 i32) (param $p1 i32) (param $p2 i32) (result i32)
    (local $l3 i32) (local $l4 i32) (local $l5 i32) (local $l6 i32) (local $l7 i32) (local $l8 i32) (local $l9 i32) (local $l10 i32)
    global.get $g0
    local.set $l3
    i32.const 16
    local.set $l4
    local.get $l3
    local.get $l4
    i32.sub
    local.set $l5
    local.get $l5
    local.get $p0
    i32.store offset=12
    local.get $l5
    local.get $p1
    i32.store offset=8
    local.get $l5
    local.get $p2
    i32.store offset=4
    local.get $l5
    i32.load offset=12
    local.set $l6
    local.get $l5
    i32.load offset=8
    local.set $l7
    local.get $l6
    local.get $l7
    i32.add
    local.set $l8
    local.get $l5
    i32.load offset=4
    local.set $l9
    local.get $l8
    local.get $l9
    i32.mul
    local.set $l10
    local.get $l10
    return)
  (func $f2 (type $t5) (param $p0 i32) (param $p1 i32)
    (local $l2 i32) (local $l3 i32) (local $l4 i32) (local $l5 i32) (local $l6 i32) (local $l7 i32) (local $l8 i32) (local $l9 i32) (local $l10 i32) (local $l11 i32) (local $l12 i32) (local $l13 i32) (local $l14 i32) (local $l15 i32) (local $l16 i32) (local $l17 i32) (local $l18 i32) (local $l19 i32) (local $l20 i32) (local $l21 i32) (local $l22 i32) (local $l23 i32) (local $l24 i32) (local $l25 i32) (local $l26 i32) (local $l27 i32)
    global.get $g0
    local.set $l2
    i32.const 16
    local.set $l3
    local.get $l2
    local.get $l3
    i32.sub
    local.set $l4
    local.get $l4
    local.get $p0
    i32.store offset=12
    local.get $l4
    local.get $p1
    i32.store offset=8
    i32.const 0
    local.set $l5
    local.get $l4
    local.get $l5
    i32.store offset=4
    block $B0
      loop $L1
        local.get $l4
        i32.load offset=4
        local.set $l6
        local.get $l4
        i32.load offset=8
        local.set $l7
        local.get $l6
        local.set $l8
        local.get $l7
        local.set $l9
        local.get $l8
        local.get $l9
        i32.lt_s
        local.set $l10
        i32.const 1
        local.set $l11
        local.get $l10
        local.get $l11
        i32.and
        local.set $l12
        local.get $l12
        i32.eqz
        br_if $B0
        local.get $l4
        i32.load offset=12
        local.set $l13
        local.get $l4
        i32.load offset=4
        local.set $l14
        local.get $l13
        local.get $l14
        i32.add
        local.set $l15
        local.get $l15
        i32.load8_u
        local.set $l16
        i32.const 24
        local.set $l17
        local.get $l16
        local.get $l17
        i32.shl
        local.set $l18
        local.get $l18
        local.get $l17
        i32.shr_s
        local.set $l19
        i32.const 100
        local.set $l20
        local.get $l19
        local.get $l20
        i32.mul
        local.set $l21
        local.get $l4
        i32.load offset=12
        local.set $l22
        local.get $l4
        i32.load offset=4
        local.set $l23
        local.get $l22
        local.get $l23
        i32.add
        local.set $l24
        local.get $l24
        local.get $l21
        i32.store8
        local.get $l4
        i32.load offset=4
        local.set $l25
        i32.const 1
        local.set $l26
        local.get $l25
        local.get $l26
        i32.add
        local.set $l27
        local.get $l4
        local.get $l27
        i32.store offset=4
        br $L1
      end
      unreachable
    end
    return)
  (func $f3 (type $t0) (result i32)
    (local $l0 i32) (local $l1 i32) (local $l2 i32) (local $l3 i32) (local $l4 i32) (local $l5 i32) (local $l6 i32) (local $l7 i32) (local $l8 i32) (local $l9 i32) (local $l10 i32) (local $l11 i32)
    global.get $g0
    local.set $l0
    i32.const 16
    local.set $l1
    local.get $l0
    local.get $l1
    i32.sub
    local.set $l2
    local.get $l2
    global.set $g0
    i32.const 1
    local.set $l3
    i32.const 2
    local.set $l4
    i32.const 3
    local.set $l5
    local.get $l3
    local.get $l4
    local.get $l5
    call $f1
    drop
    i32.const 1024
    local.set $l6
    local.get $l2
    local.get $l6
    i32.store offset=12
    local.get $l2
    i32.load offset=12
    local.set $l7
    i32.const 10
    local.set $l8
    local.get $l7
    local.get $l8
    call $f2
    i32.const 0
    local.set $l9
    i32.const 16
    local.set $l10
    local.get $l2
    local.get $l10
    i32.add
    local.set $l11
    local.get $l11
    global.set $g0
    local.get $l9
    return)
  (func $main (type $t6) (param $p0 i32) (param $p1 i32) (result i32)
    (local $l2 i32)
    call $f3
    local.set $l2
    local.get $l2
    return)
  (func $stackSave (type $t0) (result i32)
    global.get $g0)
  (func $stackRestore (type $t1) (param $p0 i32)
    local.get $p0
    global.set $g0)
  (func $stackAlloc (type $t3) (param $p0 i32) (result i32)
    (local $l1 i32) (local $l2 i32)
    global.get $g0
    local.get $p0
    i32.sub
    i32.const -16
    i32.and
    local.tee $l1
    global.set $g0
    local.get $l1)
  (func $emscripten_stack_init (type $t2)
    i32.const 5243936
    global.set $g2
    i32.const 1052
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    global.set $g1)
  (func $emscripten_stack_get_free (type $t0) (result i32)
    global.get $g0
    global.get $g1
    i32.sub)
  (func $emscripten_stack_get_base (type $t0) (result i32)
    global.get $g2)
  (func $emscripten_stack_get_end (type $t0) (result i32)
    global.get $g1)
  (func $f12 (type $t1) (param $p0 i32))
  (func $f13 (type $t1) (param $p0 i32))
  (func $f14 (type $t0) (result i32)
    i32.const 1036
    call $f12
    i32.const 1040)
  (func $f15 (type $t2)
    i32.const 1036
    call $f13)
  (func $f16 (type $t3) (param $p0 i32) (result i32)
    i32.const 1)
  (func $f17 (type $t1) (param $p0 i32))
  (func $fflush (type $t3) (param $p0 i32) (result i32)
    (local $l1 i32) (local $l2 i32) (local $l3 i32)
    block $B0
      local.get $p0
      br_if $B0
      i32.const 0
      local.set $l1
      block $B1
        i32.const 0
        i32.load offset=1044
        i32.eqz
        br_if $B1
        i32.const 0
        i32.load offset=1044
        call $fflush
        local.set $l1
      end
      block $B2
        i32.const 0
        i32.load offset=1044
        i32.eqz
        br_if $B2
        i32.const 0
        i32.load offset=1044
        call $fflush
        local.get $l1
        i32.or
        local.set $l1
      end
      block $B3
        call $f14
        i32.load
        local.tee $p0
        i32.eqz
        br_if $B3
        loop $L4
          i32.const 0
          local.set $l2
          block $B5
            local.get $p0
            i32.load offset=76
            i32.const 0
            i32.lt_s
            br_if $B5
            local.get $p0
            call $f16
            local.set $l2
          end
          block $B6
            local.get $p0
            i32.load offset=20
            local.get $p0
            i32.load offset=28
            i32.eq
            br_if $B6
            local.get $p0
            call $fflush
            local.get $l1
            i32.or
            local.set $l1
          end
          block $B7
            local.get $l2
            i32.eqz
            br_if $B7
            local.get $p0
            call $f17
          end
          local.get $p0
          i32.load offset=56
          local.tee $p0
          br_if $L4
        end
      end
      call $f15
      local.get $l1
      return
    end
    i32.const 0
    local.set $l2
    block $B8
      local.get $p0
      i32.load offset=76
      i32.const 0
      i32.lt_s
      br_if $B8
      local.get $p0
      call $f16
      local.set $l2
    end
    block $B9
      block $B10
        block $B11
          local.get $p0
          i32.load offset=20
          local.get $p0
          i32.load offset=28
          i32.eq
          br_if $B11
          local.get $p0
          i32.const 0
          i32.const 0
          local.get $p0
          i32.load offset=36
          call_indirect (type $t4) $__indirect_function_table
          drop
          local.get $p0
          i32.load offset=20
          br_if $B11
          i32.const -1
          local.set $l1
          local.get $l2
          br_if $B10
          br $B9
        end
        block $B12
          local.get $p0
          i32.load offset=4
          local.tee $l1
          local.get $p0
          i32.load offset=8
          local.tee $l3
          i32.eq
          br_if $B12
          local.get $p0
          local.get $l1
          local.get $l3
          i32.sub
          i64.extend_i32_s
          i32.const 1
          local.get $p0
          i32.load offset=40
          call_indirect (type $t7) $__indirect_function_table
          drop
        end
        i32.const 0
        local.set $l1
        local.get $p0
        i32.const 0
        i32.store offset=28
        local.get $p0
        i64.const 0
        i64.store offset=16
        local.get $p0
        i64.const 0
        i64.store offset=4 align=4
        local.get $l2
        i32.eqz
        br_if $B9
      end
      local.get $p0
      call $f17
    end
    local.get $l1)
  (func $__errno_location (type $t0) (result i32)
    i32.const 1048)
  (table $__indirect_function_table 1 1 funcref)
  (memory $memory 256 256)
  (global $g0 (mut i32) (i32.const 5243936))
  (global $g1 (mut i32) (i32.const 0))
  (global $g2 (mut i32) (i32.const 0))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "main" (func $main))
  (export "__errno_location" (func $__errno_location))
  (export "fflush" (func $fflush))
  (export "emscripten_stack_init" (func $emscripten_stack_init))
  (export "emscripten_stack_get_free" (func $emscripten_stack_get_free))
  (export "emscripten_stack_get_base" (func $emscripten_stack_get_base))
  (export "emscripten_stack_get_end" (func $emscripten_stack_get_end))
  (export "stackSave" (func $stackSave))
  (export "stackRestore" (func $stackRestore))
  (export "stackAlloc" (func $stackAlloc))
  (export "__indirect_function_table" (table 0))
  (data $d0 (i32.const 1024) "hello world\00"))
