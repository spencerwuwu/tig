Require Import RTOSDemo_NoAsserts_Clz.
Require Import riscvTiming.
Import RISCVNotations.
Require Import timing_auto.

Variable ML : N.
Variable ML_pos : 1 <= ML.

Definition time_mem : N :=
    5 + (ML - 2).
Definition time_branch : N :=
    5 + (ML - 1).
Definition time_inf : N :=
    9999.

(* Common for all timing proofs - facilitates automation *)
Module uxListRemoveTime <: TimingModule.
Definition time_of_addr (s : store) (a : addr) : N :=
    match neorv32_cycles_upper_bound ML s (RTOSDemo_NoAsserts_Clz a) with
    | Some x => x | _ => 999 end.

Definition entry_addr : N := 0x80002440.

Definition exits (t:trace) : bool :=
    match t with (Addr a,_)::_ => match a with
    | 0x80002460 => true
    | _ => false
  end | _ => false end.
End uxListRemoveTime.
Module uxListRemoveAuto := TimingAutomation uxListRemoveTime.
Import uxListRemoveTime uxListRemoveAuto.


Definition CLZ (n : N) : N := clz(n) 32.


(* Postcondition *)
Definition time_of_uxListRemove (t : trace)
  (mem : addr -> N)
  (reg_init_a0_22245_32 : N)	(* a0 *)
  : Prop :=
    cycle_count_of_trace t =
(* 0x80002440 *)   time_mem + time_mem + time_mem + time_mem + time_mem + time_mem
                   + (if negb(mem Ⓓ[mem Ⓓ[reg_init_a0_22245_32 + 0x10] + 0x4] =? reg_init_a0_22245_32)
                     then
                       5 + (ML - 1) + 
(* 0x80002460 *)       time_mem + time_mem + 2 + time_mem + time_branch
                     else
                       3 + 
(* 0x8000245c *)       time_mem +
(* 0x80002460 *)         time_mem + time_mem + 2 + time_mem + time_branch
                     ).


(* Memory Regions *)
Definition memory_regions
  (mem : addr -> N)
  (reg_init_a0_22245_32 : N)	(* a0 *)
    := map (fun x => (4, x)) [
		mem Ⓓ[reg_init_a0_22245_32 + 0x4] + 0x8;
		reg_init_a0_22245_32 + 0x10;
		mem Ⓓ[reg_init_a0_22245_32 + 0x10] + 0x4;
		reg_init_a0_22245_32 + 0x4;
		mem Ⓓ[reg_init_a0_22245_32 + 0x10];
		reg_init_a0_22245_32 + 0x8;
		mem Ⓓ[reg_init_a0_22245_32 + 0x8] + 0x4
      ].

Definition noverlaps
  (mem : addr -> N)
  (reg_init_a0_22245_32 : N)	(* a0 *)
    :=  create_noverlaps (memory_regions mem reg_init_a0_22245_32).


(* Invariants *)
(* TODO *)


(* Lift the program *)
Definition lifted_uxListRemove : program :=
    lift_riscv RTOSDemo_NoAsserts_Clz.


(* Proof *)
(* TODO *)