package qualification

import "syscall"

func planChangeTime(st *syscall.Stat_t) syscall.Timespec { return st.Ctim }
