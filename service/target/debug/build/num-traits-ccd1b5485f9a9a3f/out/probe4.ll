; ModuleID = 'probe4.903a695b-cgu.0'
source_filename = "probe4.903a695b-cgu.0"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx11.0.0"

@alloc_e4e8d3400fa234130cf37ebe97f8fce8 = private unnamed_addr constant <{ [75 x i8] }> <{ [75 x i8] c"/rustc/af06dce64bf87ea9206bdf6cff61c144b9ce8458/library/core/src/num/mod.rs" }>, align 1
@alloc_16251a3dafb17d2a782f13794ab5f568 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_e4e8d3400fa234130cf37ebe97f8fce8, [16 x i8] c"K\00\00\00\00\00\00\00/\04\00\00\05\00\00\00" }>, align 8
@str.0 = internal constant [25 x i8] c"attempt to divide by zero"

; probe4::probe
; Function Attrs: uwtable
define void @_ZN6probe45probe17h80ece558ac357a03E() unnamed_addr #0 {
start:
  %0 = call i1 @llvm.expect.i1(i1 false, i1 false)
  br i1 %0, label %panic.i, label %"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17ha086bea7c49827eeE.exit"

panic.i:                                          ; preds = %start
; call core::panicking::panic
  call void @_ZN4core9panicking5panic17h5a429dace657943eE(ptr align 1 @str.0, i64 25, ptr align 8 @alloc_16251a3dafb17d2a782f13794ab5f568) #3
  unreachable

"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17ha086bea7c49827eeE.exit": ; preds = %start
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.expect.i1(i1, i1) #1

; core::panicking::panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking5panic17h5a429dace657943eE(ptr align 1, i64, ptr align 8) unnamed_addr #2

attributes #0 = { uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-a14" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { cold noinline noreturn uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-a14" }
attributes #3 = { noreturn }

!llvm.module.flags = !{!0}

!0 = !{i32 8, !"PIC Level", i32 2}
