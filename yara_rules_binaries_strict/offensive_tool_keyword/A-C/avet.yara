rule avet
{
    meta:
        description = "Detection patterns for the tool 'avet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string1 = /\/avet\.git/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string2 = /\/avet_script_config\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string3 = /\\avetdbg\.txt/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string4 = "add_evasion check_fast_forwarding" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string5 = "add_evasion computation_fibonacci " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string6 = "add_evasion computation_timed_fibonacci" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string7 = "add_evasion evasion_by_sleep " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string8 = "add_evasion fopen_sandbox_evasion" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string9 = "add_evasion get_bios_info" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string10 = "add_evasion get_computer_domain " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string11 = "add_evasion get_cpu_cores " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string12 = "add_evasion get_install_date " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string13 = "add_evasion get_num_processes" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string14 = "add_evasion get_standard_browser " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string15 = "add_evasion get_tickcount" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string16 = "add_evasion gethostbyname_sandbox_evasion" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string17 = "add_evasion has_background_wp" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string18 = "add_evasion has_folder " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string19 = "add_evasion has_network_drive" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string20 = "add_evasion has_public_desktop" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string21 = "add_evasion has_recent_files" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string22 = "add_evasion has_recycle_bin" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string23 = "add_evasion has_username " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string24 = "add_evasion has_vm_mac" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string25 = "add_evasion has_vm_regkey" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string26 = "add_evasion hide_console" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string27 = "add_evasion interaction_getchar" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string28 = "add_evasion interaction_system_pause" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string29 = "add_evasion is_debugger_present" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string30 = "add_evasion sleep_by_ping " nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string31 = /avet\-master\.zip/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string32 = /build_40xshikata_revhttpsunstaged_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string33 = /build_50xshikata_quiet_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string34 = /build_50xshikata_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string35 = /build_asciimsf_fromcmd_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string36 = /build_asciimsf_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string37 = /build_avetenc_dynamicfromfile_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string38 = /build_avetenc_fopen_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string39 = /build_avetenc_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string40 = /build_calcfromcmd_50xshikata_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string41 = /build_calcfrompowersh_50xshikata_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string42 = /build_checkdomain_rc4_mimikatz\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string43 = /build_disablewindefpsh_xorfromcmd_revhttps_win64\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string44 = /build_dkmc_downloadexecshc_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string45 = /build_downloadbitsadmin_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string46 = /build_downloadbitsadmin_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string47 = /build_downloadcertutil_revhttps_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string48 = /build_downloadcurl_mtrprtrxor_revhttps_win64\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string49 = /build_sleep_rc4_mimikatz\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string50 = /build_svc_20xshikata_bindtcp_win32\.sh/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string51 = /encode_payload\src4\s.{0,100}\.txt/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string52 = /evasion\/has_recycle_bin\./ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string53 = "govolution/avet" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string54 = /input\/shellcode_enc_raw\.txt/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string55 = /input\/shellcode_raw\.txt/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string56 = /pe2shc\.exe/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string57 = /pe2shc_.{0,100}\.zip/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string58 = "set_command_exec exec_via_cmd" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string59 = "set_command_exec exec_via_powershell" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string60 = "set_command_exec no_command" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string61 = "set_command_source download_bitsadmin" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string62 = "set_decoder xor" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string63 = "set_payload_execution_method exec_shellcode64" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string64 = "set_payload_execution_method inject_dll" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string65 = "set_payload_info_source from_command_line_raw" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string66 = "set_payload_source download_powershell" nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string67 = /source\/avetsvc\.c/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
