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
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string19 = /_ppl_dump\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string20 = /_ppl_dump\.x64\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string21 = /_ppl_dump_dll\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string22 = /_ppl_dump_dll\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string23 = /_ppl_medic\.x64\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string24 = /_ppl_medic\.x64\.exe/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string25 = /_ppl_medic_dll\.x64\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string26 = /08f0007bf2c941bb9372682e9cdcc21e59369b6038c70a7a20a7d3507abaa86d/ nocase ascii wide
        // Description: nanodump string minidump
        // Reference: https://github.com/Meowmycks/LetMeowIn
        $string27 = /0x4d\,\s0x44\,\s0x4d\,\s0x50\,\s0x93\,\s0xa7\,\s0x00\,\s0x00/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string28 = /2202732c2585283f93fca9bee4c3f3709530fa450a1bea8bfb925768f38b2bb9/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string29 = /4a25a09ed816e1c629945dbd33779ab714d82bebf661557864aa61562ed4298c/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string30 = /567639e3dc4355c549e9c9cc42988325cb95a0f6e86004d5679ad3e15af7c6cd/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string31 = /56a0e08a01309e17e4e6c753948fd4f341e9a41b1b834b3ce697bffdd90c467b/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string32 = /79ef2d4f2ad91311f14fc200acb71e78a47eb9a4f23e776649fb1b0b06c69dd2/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string33 = /83536b1df51e5954c757179b70419fe5567df58f3ed029998e6ca82f7c0a15a7/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string34 = /8484a8848d429d954636f8c6c170bdd73d96288325b902eb43c3403f0650b5e6/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string35 = /8a24643b1ae79babbba0995d870bf0992cfc9acfef6459727c603ef5b61c261f/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string36 = /90e767d5fd29fc406847b5ac6151a713643596625209245d3440fd8908ff7427/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string37 = /97699449246070bc8195e1cf1f14b94dc2ee429cb03128bb7e7e254981eb71a0/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string38 = /a909221a35b3fda0f6149de8e58186909cd0efae15bbba614b9a15d4b7d15fd3/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string39 = /be9cd67ca6ef0d87c8dacebef75d1f62b38cff5b8ba4ad2f0eb382ab54081317/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string40 = /c18989d8b80f11117c403bc1c8f8afac0a807f1acdf67ecffcf50402164c11eb/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string41 = /cdcb96e58514e182d0799884b64872caff34ed0eb552d842015941a7540347e7/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string42 = /check_ppl_requirements/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string43 = /create_dummy_dll_file/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string44 = /create_protected_process_as_user/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string45 = /d854d2be5826183cb7c1317e3d920871fd467d5506b70e3c5147599ca2704ee6/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string46 = /f2ca48973b72ab97f4cb482062d2ab8778078107767a36062e11243a3265e756/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string47 = /f3bdfbd2b36064266a9d9e4452aba93cb97980c37dbe472e0b3b72e1485500ab/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string48 = /faa491fa7733cf0c51ffdcf97be3fd48231863ff59b4f6922e11bbb747bf1806/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string49 = /get_hijackeable_dllname/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string50 = /initialize_fake_thread_state/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string51 = /initialize_spoofed_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string52 = /is_proxy_stub_dll_loaded/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string53 = /load_ssp\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string54 = /load_ssp\.x64\.exe\s.{0,1000}\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string55 = /map_payload_dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string56 = /nanodump\s/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string57 = /nanodump\s\-/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string58 = /nanodump\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string59 = /nanodump\.git/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string60 = /nanodump\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string61 = /nanodump\.x64\.exe/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string62 = /nanodump\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string63 = /nanodump_ppl_dump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string64 = /nanodump_ppl_dump\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string65 = /nanodump_ppl_dump\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string66 = /nanodump_ppl_medic/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string67 = /nanodump_ppl_medic\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string68 = /nanodump_ppl_medic\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string69 = /nanodump_ssp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string70 = /nanodump_ssp\.x64/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string71 = /nanodump_ssp\.x64\.dll/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string72 = /nanodump_ssp\.x86/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string73 = /NanoDumpWriteDump/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string74 = /ppl.{0,1000}\s\-\-elevate\-handle\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string75 = /ppl_medic_dll\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string76 = /prepare_ppl_command_line/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string77 = /print_shtinkering_crash_location/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string78 = /randomize_sw2_seed\.py/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string79 = /restore_signature\.sh\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string80 = /run_ppl_dump_exploit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string81 = /run_ppl_medic_exploit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string82 = /\-\-seclogon\-leak\-local/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string83 = /\-\-seclogon\-leak\-remote/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string84 = /set_rpc_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string85 = /set_svchost_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string86 = /set_wmi_callstack/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string87 = /source\/shtinkering\./ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string88 = /\-\-spoof\-callstack\s/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string89 = /SW2_GetSyscallNumber/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string90 = /SW2_PopulateSyscallList/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string91 = /SW2_RVA2VA/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string92 = /SW3_GetSyscallAddress/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string93 = /werfault_shtinkering/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string94 = /werfault_silent_process_exit/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string95 = /write_payload_dll_transacted/ nocase ascii wide
        // Description: The swiss army knife of LSASS dumping. A flexible tool that creates a minidump of the LSASS process.
        // Reference: https://github.com/fortra/nanodump
        $string96 = /nanodump/ nocase ascii wide

    condition:
        any of them
}
