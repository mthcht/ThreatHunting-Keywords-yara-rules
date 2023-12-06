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
        $string4 = /add_evasion\scheck_fast_forwarding/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string5 = /add_evasion\scomputation_fibonacci\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string6 = /add_evasion\scomputation_timed_fibonacci/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string7 = /add_evasion\sevasion_by_sleep\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string8 = /add_evasion\sfopen_sandbox_evasion/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string9 = /add_evasion\sget_bios_info/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string10 = /add_evasion\sget_computer_domain\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string11 = /add_evasion\sget_cpu_cores\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string12 = /add_evasion\sget_install_date\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string13 = /add_evasion\sget_num_processes/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string14 = /add_evasion\sget_standard_browser\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string15 = /add_evasion\sget_tickcount/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string16 = /add_evasion\sgethostbyname_sandbox_evasion/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string17 = /add_evasion\shas_background_wp/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string18 = /add_evasion\shas_folder\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string19 = /add_evasion\shas_network_drive/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string20 = /add_evasion\shas_public_desktop/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string21 = /add_evasion\shas_recent_files/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string22 = /add_evasion\shas_recycle_bin/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string23 = /add_evasion\shas_username\s/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string24 = /add_evasion\shas_vm_mac/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string25 = /add_evasion\shas_vm_regkey/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string26 = /add_evasion\shide_console/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string27 = /add_evasion\sinteraction_getchar/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string28 = /add_evasion\sinteraction_system_pause/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string29 = /add_evasion\sis_debugger_present/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string30 = /add_evasion\ssleep_by_ping\s/ nocase ascii wide
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
        $string51 = /encode_payload\src4\s.{0,1000}\.txt/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string52 = /evasion\/has_recycle_bin\./ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string53 = /govolution\/avet/ nocase ascii wide
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
        $string57 = /pe2shc_.{0,1000}\.zip/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string58 = /set_command_exec\sexec_via_cmd/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string59 = /set_command_exec\sexec_via_powershell/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string60 = /set_command_exec\sno_command/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string61 = /set_command_source\sdownload_bitsadmin/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string62 = /set_decoder\sxor/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string63 = /set_payload_execution_method\sexec_shellcode64/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string64 = /set_payload_execution_method\sinject_dll/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string65 = /set_payload_info_source\sfrom_command_line_raw/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string66 = /set_payload_source\sdownload_powershell/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string67 = /source\/avetsvc\.c/ nocase ascii wide

    condition:
        any of them
}
