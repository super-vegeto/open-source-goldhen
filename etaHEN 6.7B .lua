-- Basic process killer (run after the jailbreak)
-- Kills processes whose name contains any string in TARGETS.

print("open source goldhen lalalalalala")

local TARGETS = {
    "elfldr",   -- ELF loader
    "pldmgr",   -- PS5 Payload Manager (pldmgr.elf)
}

-- FreeBSD 11 amd64 kinfo_proc offsets
local KI_PID_OFF  = 72
local KI_COMM_OFF = 447
local COMMLEN     = 19

local SIGKILL = 9

syscall.resolve({
    getpid = 20,
    kill   = 37,
    sysctl = 202,
})

local my_pid = tonumber(syscall.getpid():tonumber())

-- sysctl mib: kern.proc.all = { CTL_KERN=1, KERN_PROC=14, KERN_PROC_ALL=0 }
local mib = memory.alloc(16)
memory.write_dword(mib,      1)
memory.write_dword(mib + 4,  14)
memory.write_dword(mib + 8,  0)

-- First call: ask how big the process list is
local len_ptr = memory.alloc(8)
memory.write_qword(len_ptr, 0)
syscall.sysctl(mib, 3, 0, len_ptr, 0, 0)
local size = tonumber(memory.read_qword(len_ptr):tonumber()) + 4096

-- Second call: fetch it
local buf = memory.alloc(size)
memory.write_qword(len_ptr, size)
syscall.sysctl(mib, 3, buf, len_ptr, 0, 0)
local total = tonumber(memory.read_qword(len_ptr):tonumber())

local function matches(name)
    name = name:lower()
    for _, t in ipairs(TARGETS) do
        if name:find(t:lower(), 1, true) then return true end
    end
    return false
end

local killed = 0
local offset = 0
while offset < total do
    local entry   = buf + offset
    local struct_size = memory.read_dword(entry)  -- ki_structsize
    if struct_size == 0 then break end

    local pid  = memory.read_dword(entry + KI_PID_OFF)
    local comm = memory.read_buffer(entry + KI_COMM_OFF, COMMLEN)
    comm = comm:match("^[^%z]*") or ""

    if pid ~= my_pid and matches(comm) then
        local ret = syscall.kill(pid, SIGKILL)
        print(string.format("kill %s (pid %d) -> %s", comm, pid, tostring(ret)))
        killed = killed + 1
    end

    offset = offset + struct_size
end

print(string.format("done, killed %d process(es)", killed))
