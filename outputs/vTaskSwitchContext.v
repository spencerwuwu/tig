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
Module vTaskSwitchContextTime <: TimingModule.
  Definition time_of_addr (s : store) (a : addr) : N :=
      match neorv32_cycles_upper_bound ML s (RTOSDemo_NoAsserts_Clz a) with
      | Some x => x | _ => 999 end.
  
  Definition entry_addr : N := 0x8000137c.
  
  Definition exits (t:trace) : bool :=
      match t with (Addr a,_)::_ => match a with
      | 0x80001384| 0x80001424 => true
      | _ => false
    end | _ => false end.
End vTaskSwitchContextTime.
Module vTaskSwitchContextAuto := TimingAutomation vTaskSwitchContextTime.
Import vTaskSwitchContextTime vTaskSwitchContextAuto.


Definition CLZ (n : N) : N := clz(n) 32.


(* Postcondition *)
Definition time_of_vTaskSwitchContext (t : trace)
    (mem : addr -> N)
    reg_init_sp_22241_32
    reg_init_gp_22242_32
  : Prop :=
    cycle_count_of_trace t =
(* 0x8000137c *)   time_mem
                   + (if mem Ⓓ[reg_init_gp_22242_32 + 0xfffff860] =? 0x0
                     then
                       time_branch + 
(* 0x80001390 *)       2 + time_mem + time_mem + time_mem + 2 + time_mem + time_mem + 2 + time_mem
                       + (if negb(mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30]] =? 0xa5a5a5a5)
                         then
                           time_branch + 
(* 0x800013d0 *)           time_inf
                         else
                           3 + 
(* 0x800013b8 *)           time_mem
                           + (if negb(mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x4] =? mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30]])
                             then
                               time_branch + 
(* 0x800013d0 *)               time_inf
                             else
                               3 + 
(* 0x800013c0 *)               time_mem
                               + (if negb(mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x8] =? mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x4])
                                 then
                                   time_branch + 
(* 0x800013d0 *)                   time_inf
                                 else
                                   3 + 
(* 0x800013c8 *)                   time_mem
                                   + (if mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0xc] =? mem Ⓓ[mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x8]
                                     then
                                       time_branch + 
(* 0x800013e0 *)                       time_mem + 2 + (3 + clz (mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) 32) + 2 + 2 + 36 + 2 + 2 + 2 + time_mem + 2 + 2 + time_mem + time_mem
                                       + (if negb(mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4] + 0x4] =? 0xfffffed8 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + reg_init_gp_22242_32)
                                         then
                                           time_branch + 
(* 0x80001424 *)                           2 + 36 + time_mem + 2 + time_mem + time_mem + time_mem + time_mem + time_mem + 2 + time_branch
                                         else
                                           3 + 
(* 0x8000141c *)                           time_mem + time_mem +
(* 0x80001424 *)                           2 + 36 + time_mem + 2 + time_mem + time_mem + time_mem + time_mem + time_mem + 2 + time_branch
                                         )
                                     else
                                       3 + 
(* 0x800013d0 *)                       time_inf
                                     )
                                 )
                             )
                         )
                     else
                       3 + 
(* 0x80001384 *)       2 + time_mem + time_branch
                     ).


(* Memory Regions *)
Definition memory_regions
    (mem : addr -> N)
    (reg_init_sp_22241_32 : N)	(* sp *)
    (reg_init_gp_22242_32 : N)	(* gp *)
    := map (fun x => (4, x)) [
		reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4;
		mem Ⓓ[reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4] + 0xc;
		mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30;
		mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x8;
		reg_init_sp_22241_32 + 0xfffffffc;
		reg_init_sp_22241_32 + 0xfffffff8;
		mem Ⓓ[reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4] + 0x4;
		reg_init_gp_22242_32 + 0xfffff874;
		reg_init_gp_22242_32 + 0xfffff880;
		reg_init_gp_22242_32 + 0xfffff860;
		reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffedc;
		mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30];
		reg_init_gp_22242_32 + 0xfffff898;
		mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0xc;
		mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x4
      ].

Definition noverlaps
    (mem : addr -> N)
    (reg_init_sp_22241_32 : N)	(* sp *)
    (reg_init_gp_22242_32 : N)	(* gp *)
    :=  create_noverlaps (memory_regions mem ['reg_init_sp_22241_32', 'reg_init_gp_22242_32']).


(* Invariants *)
Definition vTaskSwitchContext_timing_invs 
    (mem : addr -> N)
    (reg_init_sp_22241_32 : N)	(* sp *)
    (reg_init_gp_22242_32 : N)	(* gp *)
    (t : trace) : option Prop :=
match t with (Addr a, s) :: t' => match a with
| 0x8000137c => Some (s R_SP = Ⓓreg_init_sp_22241_32 /\
			s R_GP = Ⓓreg_init_gp_22242_32 /\
			s V_MEM32 = Ⓜmem /\
			noverlaps mem reg_init_sp_22241_32 reg_init_gp_22242_32 /\
			cycle_count_of_trace t' = 0)
| 0x80001424 => Some (exists mem, s V_MEM32 = Ⓜmem /\
			noverlaps mem reg_init_sp_22241_32 reg_init_gp_22242_32 /\
			cycle_count_of_trace t' =   
  (* 0x8000137c *)   time_mem + 
                       time_branch + 
  (* 0x80001390 *)   2 + time_mem + time_mem + time_mem + 2 + time_mem + time_mem + 2 + time_mem + 
                       3 + 
  (* 0x800013b8 *)   time_mem + 
                       3 + 
  (* 0x800013c0 *)   time_mem + 
                       3 + 
  (* 0x800013c8 *)   time_mem + 
                       time_branch + 
  (* 0x800013e0 *)   time_mem + 2 + (3 + clz (mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) 32) + 2 + 2 + 36 + 2 + 2 + 2 + time_mem + 2 + 2 + time_mem + time_mem
                     + (if negb(mem Ⓓ[mem Ⓓ[reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4] + 0x4] =? 0xfffffed8 + 0xffffffec * CLZ(mem Ⓓ[reg_init_gp_22242_32 + 0xfffff880]) + reg_init_gp_22242_32)
                       then
                         time_branch + 0
                       else
                         3 + 
  (* 0x8000141c *)       time_mem + time_mem + 0
                       )
		)
| 0x80001384 | 0x80001424  => Some (exists mem, s V_MEM32 = Ⓜmem /\
			time_of_vTaskSwitchContext t mem reg_init_sp_22241_32 reg_init_gp_22242_32)
| _ => None end | _ => None end
.


(* Lift the program *)
Definition lifted_vTaskSwitchContext : program :=
    lift_riscv RTOSDemo_NoAsserts_Clz.


(* Proof *)
(* TODO *)