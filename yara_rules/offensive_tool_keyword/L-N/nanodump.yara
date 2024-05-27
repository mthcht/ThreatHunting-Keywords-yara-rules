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
        $string1 = /\s\-\-fork\s\-\-write\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string2 = /\s\-\-load\-dll\s.{0,1000}ssp\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string3 = /\snanodump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string4 = /\snanodump\// nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string5 = /\s\-\-seclogon\-duplicate/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string6 = /\s\-\-shtinkering/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string7 = /\s\-\-silent\-process\-exit\s/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string8 = /\sSW2_HashSyscall/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string9 = /\s\-\-werfault\s.{0,1000}\\temp\\/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string10 = /\/load_ssp\.x64\.exe/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string11 = /\/malseclogon\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string12 = /\/nanodump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string13 = /\/ppl\/ppl\.c/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string14 = /\/ppl_dump\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string15 = /\\load_ssp\.x64\.exe/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string16 = /\\malseclogon\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string17 = /\\nanodump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string18 = /\\ppl_dump\./ nocase ascii wide
        // Description: nanodump string minidump
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string19 = /0x4d\,\s0x44\,\s0x4d\,\s0x50\,\s0x93\,\s0xa7\,\s0x00\,\s0x00/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string20 = /check_ppl_requirements/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string21 = /create_dummy_dll_file/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string22 = /create_protected_process_as_user/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string23 = /get_hijackeable_dllname/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string24 = /initialize_fake_thread_state/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string25 = /initialize_spoofed_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string26 = /is_proxy_stub_dll_loaded/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string27 = /load_ssp\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string28 = /load_ssp\.x64\.exe\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string29 = /map_payload_dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string30 = /nanodump\s/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string31 = /nanodump\s\-/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string32 = /nanodump\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string33 = /nanodump\.git/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string34 = /nanodump\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string35 = /nanodump\.x64\.exe/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string36 = /nanodump\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string37 = /nanodump_ppl_dump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string38 = /nanodump_ppl_dump\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string39 = /nanodump_ppl_dump\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string40 = /nanodump_ppl_medic/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string41 = /nanodump_ppl_medic\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string42 = /nanodump_ppl_medic\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string43 = /nanodump_ssp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string44 = /nanodump_ssp\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string45 = /nanodump_ssp\.x64\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string46 = /nanodump_ssp\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string47 = /NanoDumpWriteDump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string48 = /ppl.{0,1000}\s\-\-elevate\-handle\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string49 = /ppl_medic_dll\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string50 = /prepare_ppl_command_line/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string51 = /print_shtinkering_crash_location/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string52 = /randomize_sw2_seed\.py/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string53 = /restore_signature\.sh\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string54 = /run_ppl_dump_exploit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string55 = /run_ppl_medic_exploit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string56 = /\-\-seclogon\-leak\-local/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string57 = /\-\-seclogon\-leak\-remote/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string58 = /set_rpc_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string59 = /set_svchost_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string60 = /set_wmi_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string61 = /source\/shtinkering\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string62 = /\-\-spoof\-callstack\s/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string63 = /SW2_GetSyscallNumber/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string64 = /SW2_PopulateSyscallList/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string65 = /SW2_RVA2VA/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string66 = /SW3_GetSyscallAddress/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string67 = /werfault_shtinkering/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string68 = /werfault_silent_process_exit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string69 = /write_payload_dll_transacted/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string70 = /delete_file\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string71 = /nanodump/ nocase ascii wide

    condition:
        any of them
}
