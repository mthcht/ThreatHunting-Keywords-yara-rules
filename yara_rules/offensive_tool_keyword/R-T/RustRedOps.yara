rule RustRedOps
{
    meta:
        description = "Detection patterns for the tool 'RustRedOps' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustRedOps"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string1 = /\santi_analysis\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string2 = /\santi_debug\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string3 = /\sapc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string4 = /\sapi_hooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string5 = /\sargs_spoofing\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string6 = /\sblock_dll_policy\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string7 = /\scommand_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string8 = /\sdllinjection_rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string9 = /\sebapc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string10 = /\senable_all_tokens\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string11 = /\sencryption_aes\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string12 = /\sencryption_rc4\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string13 = /\senumeration_process\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string14 = /\sexecute_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string15 = /\sextract_wifi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string16 = /\siat_obfuscation\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string17 = /\slfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string18 = /\slocal_execution_linux\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string19 = /\slocal_map\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string20 = /\slocal_thread_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string21 = /\sminidump\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string22 = /\sntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string23 = /\sntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string24 = /\sobfuscation\.exe\s\-\-help/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string25 = /\s\-p\swindows\/x64\/exec\sCMD\=.{0,1000}\.exe\s\-f\srust/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string26 = /\spatch_amsi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string27 = /\spatch_etw\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string28 = /\spayload_placement\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string29 = /\sppid_spoofing\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string30 = /\sprocessinjection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string31 = /\sreg_recover\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string32 = /\srequest_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string33 = /\srfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string34 = /\srm_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string35 = /\srt_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string36 = /\sself_deletion\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string37 = /\sshellcode_callback\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string38 = /\swmi_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string39 = /\/anti_analysis\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string40 = /\/anti_debug\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string41 = /\/apc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string42 = /\/api_hooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string43 = /\/args_spoofing\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string44 = /\/block_dll_policy\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string45 = /\/command_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string46 = /\/dllinjection_rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string47 = /\/ebapc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string48 = /\/enable_all_tokens\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string49 = /\/encryption_aes\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string50 = /\/encryption_rc4\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string51 = /\/enumeration_process\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string52 = /\/execute_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string53 = /\/extract_wifi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string54 = /\/iat_obfuscation\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string55 = /\/lfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string56 = /\/local_execution_linux\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string57 = /\/local_map\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string58 = /\/local_thread_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string59 = /\/minidump\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string60 = /\/ntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string61 = /\/ntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string62 = /\/obfuscation\.exe\s\-\-help/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string63 = /\/patch_amsi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string64 = /\/patch_etw\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string65 = /\/payload_placement\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string66 = /\/ppid_spoofing\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string67 = /\/processinjection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string68 = /\/reg_recover\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string69 = /\/request_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string70 = /\/rfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string71 = /\/rm_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string72 = /\/rt_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string73 = /\/RustRedOps\.git/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string74 = /\/self_deletion\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string75 = /\/shellcode_callback\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string76 = /\/wmi_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string77 = /\[\+\]\sCopying\sa\sShellcode\sTo\sTarget\sMemory/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string78 = /\\\\\.\\\\pipe\\\\Teste/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string79 = /\\anti_analysis\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string80 = /\\anti_debug\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string81 = /\\apc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string82 = /\\api_hooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string83 = /\\args_spoofing\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string84 = /\\block_dll_policy\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string85 = /\\command_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string86 = /\\dllinjection_rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string87 = /\\ebapc_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string88 = /\\enable_all_tokens\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string89 = /\\encryption_aes\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string90 = /\\encryption_rc4\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string91 = /\\enumeration_process\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string92 = /\\execute_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string93 = /\\extract_wifi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string94 = /\\iat_obfuscation\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string95 = /\\lfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string96 = /\\local_execution_linux\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string97 = /\\local_map\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string98 = /\\local_thread_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string99 = /\\minidump\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string100 = /\\ntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string101 = /\\ntdll_unhooking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string102 = /\\obfuscation\.exe\s\-\-help/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string103 = /\\patch_amsi\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string104 = /\\patch_etw\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string105 = /\\payload_placement\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string106 = /\\ppid_spoofing\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string107 = /\\processinjection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string108 = /\\reg_recover\-rs\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string109 = /\\request_shellcode\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string110 = /\\rfs_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string111 = /\\rm_injection\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string112 = /\\rt_hijacking\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string113 = /\\RustRedOps\\/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string114 = /\\RustRedOps\-main/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string115 = /\\self_deletion\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string116 = /\\shellcode_callback\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string117 = /\\Tasks\\lsass\.dmp/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string118 = /\\wmi_exec\.exe/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string119 = /joaoviictorti\/RustRedOps/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string120 = /obfuscation\.exe\s\-\-/ nocase ascii wide
        // Description: RustRedOps is a repository dedicated to gathering and sharing advanced techniques and offensive malware for Red Team
        // Reference: https://github.com/joaoviictorti/RustRedOps
        $string121 = /obfuscation\.exe\s\-f\s.{0,1000}\s\-t\s/ nocase ascii wide

    condition:
        any of them
}
