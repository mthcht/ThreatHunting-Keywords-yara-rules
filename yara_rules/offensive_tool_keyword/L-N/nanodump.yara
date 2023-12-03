rule nanodump
{
    meta:
        description = "Detection patterns for the tool 'nanodump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nanodump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string1 = /.{0,1000}\s\-\-fork\s\-\-write\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string2 = /.{0,1000}\s\-\-load\-dll\s.{0,1000}ssp\.dll.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string3 = /.{0,1000}\snanodump.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string4 = /.{0,1000}\snanodump\/.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string5 = /.{0,1000}\s\-\-seclogon\-duplicate.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string6 = /.{0,1000}\s\-\-shtinkering.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string7 = /.{0,1000}\s\-\-silent\-process\-exit\s.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string8 = /.{0,1000}\sSW2_HashSyscall.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string9 = /.{0,1000}\s\-\-werfault\s.{0,1000}\\temp\\.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string10 = /.{0,1000}\/malseclogon\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string11 = /.{0,1000}\/nanodump.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string12 = /.{0,1000}\/ppl\/ppl\.c.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string13 = /.{0,1000}\/ppl_dump\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string14 = /.{0,1000}\\malseclogon\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string15 = /.{0,1000}\\nanodump.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string16 = /.{0,1000}\\ppl_dump\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string17 = /.{0,1000}check_ppl_requirements.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string18 = /.{0,1000}create_dummy_dll_file.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string19 = /.{0,1000}create_protected_process_as_user.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string20 = /.{0,1000}get_hijackeable_dllname.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string21 = /.{0,1000}initialize_fake_thread_state.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string22 = /.{0,1000}initialize_spoofed_callstack.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string23 = /.{0,1000}is_proxy_stub_dll_loaded.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string24 = /.{0,1000}load_ssp\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string25 = /.{0,1000}map_payload_dll.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string26 = /.{0,1000}nanodump\s.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string27 = /.{0,1000}nanodump\s\-.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string28 = /.{0,1000}nanodump\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string29 = /.{0,1000}nanodump\.git.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string30 = /.{0,1000}nanodump\.x64.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string31 = /.{0,1000}nanodump\.x64\.exe.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string32 = /.{0,1000}nanodump\.x86.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string33 = /.{0,1000}nanodump_ppl_dump.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string34 = /.{0,1000}nanodump_ppl_dump\.x64.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string35 = /.{0,1000}nanodump_ppl_dump\.x86.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string36 = /.{0,1000}nanodump_ppl_medic.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string37 = /.{0,1000}nanodump_ppl_medic\.x64.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string38 = /.{0,1000}nanodump_ppl_medic\.x86.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string39 = /.{0,1000}nanodump_ssp.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string40 = /.{0,1000}nanodump_ssp\.x64.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string41 = /.{0,1000}nanodump_ssp\.x64\.dll.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string42 = /.{0,1000}nanodump_ssp\.x86.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string43 = /.{0,1000}NanoDumpWriteDump.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string44 = /.{0,1000}ppl.{0,1000}\s\-\-elevate\-handle\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string45 = /.{0,1000}ppl_medic_dll\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string46 = /.{0,1000}prepare_ppl_command_line.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string47 = /.{0,1000}print_shtinkering_crash_location.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string48 = /.{0,1000}randomize_sw2_seed\.py.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string49 = /.{0,1000}restore_signature\.sh\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string50 = /.{0,1000}run_ppl_dump_exploit.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string51 = /.{0,1000}run_ppl_medic_exploit.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string52 = /.{0,1000}\-\-seclogon\-leak\-local.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string53 = /.{0,1000}\-\-seclogon\-leak\-remote.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string54 = /.{0,1000}set_rpc_callstack.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string55 = /.{0,1000}set_svchost_callstack.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string56 = /.{0,1000}set_wmi_callstack.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string57 = /.{0,1000}source\/shtinkering\..{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string58 = /.{0,1000}\-\-spoof\-callstack\s.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string59 = /.{0,1000}SW2_GetSyscallNumber.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string60 = /.{0,1000}SW2_PopulateSyscallList.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string61 = /.{0,1000}SW2_RVA2VA.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string62 = /.{0,1000}SW3_GetSyscallAddress.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string63 = /.{0,1000}werfault_shtinkering.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string64 = /.{0,1000}werfault_silent_process_exit.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string65 = /.{0,1000}write_payload_dll_transacted.{0,1000}/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string66 = /delete_file\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string67 = /nanodump.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
