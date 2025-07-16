
Definition time_of_vTaskSwitchContext (t : trace) (gp : N) (mem : addr -> N) : Prop :=
cycle_count_of_trace t =
  (* 0x8000137c *)   time_mem
                   + (if mem Ⓓ [reg_init_gp_22242_32 + 0xfffff860] == 0x0
                     then
                       5 + (ML - 1) +
(* 0x80001390 *)       2 + time_mem + time_mem + time_mem + 2 + time_mem + time_mem + 2 + time_mem
                       + (if mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30]] != 0xa5a5a5a5
                         then
                           5 + (ML - 1) +
(* 0x800013d0 *)           time_inf
                         else
                           3 +
(* 0x800013b8 *)           time_mem
                           + (if mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x4] != mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30]]
                             then
                               5 + (ML - 1) +
(* 0x800013d0 *)               time_inf
                             else
                               3 +
(* 0x800013c0 *)               time_mem
                               + (if mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x8] != mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x4]
                                 then
                                   5 + (ML - 1) +
(* 0x800013d0 *)                   time_inf
                                 else
                                   3 +
(* 0x800013c8 *)                   time_mem
                                   + (if mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0xc] == mem Ⓓ [mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xfffff898] + 0x30] + 0x8]
                                     then
                                       5 + (ML - 1) +
(* 0x800013e0 *)                       time_mem + 2 + (3 + clz (s R_A5) 32) + 2 + 2 + 36 + 2 + 2 + 2 + time_mem + 2 + 2 + time_mem + time_mem
                                       + (if mem Ⓓ [mem Ⓓ [reg_init_gp_22242_32 + 0xffffffec * CLZ(mem Ⓓ [reg_init_gp_22242_32 + 0xfffff880]) + 0xfffffed4] + 0x4] != 0xfffffed8 + 0xffffffec * CLZ(mem Ⓓ [reg_init_gp_22242_32 + 0xfffff880]) + reg_init_gp_22242_32
                                         then
                                           5 + (ML - 1) +
(* 0x80001424 *)                           2 + 36 + time_mem + 2 + time_mem + time_mem + time_mem + time_mem + time_mem + 2 + time_branch
                                         else
                                           3 +
(* 0x8000141c *)                           time_mem + time_mem +
(* 0x80001424 *)                             2 + 36 + time_mem + 2 + time_mem + time_mem + time_mem + time_mem + time_mem + 2 + time_branch
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
                     )
.

Definition time_of_vTaskSwitchContext (t : trace) (gp : N) (mem : addr -> N) : Prop :=
    if ((uxSchedulerSuspended gp mem) =? 0) = false 
    then
        cycle_count_of_trace t = 5 + time_branch + 2 * time_mem
    else
      if ((uxSchedulerSuspended gp mem) =? 0) = true /\
        ((mem Ⓓ[ 4 + mem Ⓓ[ gp ⊖ 920 ⊕ (31 ⊖ clz (uxTopReadyPriority gp mem) 32) * 20 ] ])
              =? ((gp ⊖ 916) ⊕ (31 ⊖ clz (uxTopReadyPriority gp mem) 32) * 20)
          = true 
        )
      then
        cycle_count_of_trace t = 
        25 + 3 * time_branch + 17 * time_mem
          + (if (mem Ⓓ[ 4 + mem Ⓓ[ gp ⊖ 920 ⊕ (31 ⊖ clz (uxTopReadyPriority gp mem) 32) * 20 ] ])
              then 
                22 + (clz (uxTopReadyPriority gp mem) 32) + 5 * time_mem 
      else
        cycle_count_of_trace t = 5 + time_branch + 2 * time_mem.
