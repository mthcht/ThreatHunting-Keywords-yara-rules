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
        $string1 = /.{0,1000}\/avet\.git.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string2 = /.{0,1000}\/avet_script_config\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string3 = /.{0,1000}\\avetdbg\.txt.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string4 = /.{0,1000}add_evasion\scheck_fast_forwarding.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string5 = /.{0,1000}add_evasion\scomputation_fibonacci\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string6 = /.{0,1000}add_evasion\scomputation_timed_fibonacci.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string7 = /.{0,1000}add_evasion\sevasion_by_sleep\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string8 = /.{0,1000}add_evasion\sfopen_sandbox_evasion.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string9 = /.{0,1000}add_evasion\sget_bios_info.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string10 = /.{0,1000}add_evasion\sget_computer_domain\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string11 = /.{0,1000}add_evasion\sget_cpu_cores\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string12 = /.{0,1000}add_evasion\sget_install_date\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string13 = /.{0,1000}add_evasion\sget_num_processes.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string14 = /.{0,1000}add_evasion\sget_standard_browser\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string15 = /.{0,1000}add_evasion\sget_tickcount.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string16 = /.{0,1000}add_evasion\sgethostbyname_sandbox_evasion.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string17 = /.{0,1000}add_evasion\shas_background_wp.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string18 = /.{0,1000}add_evasion\shas_folder\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string19 = /.{0,1000}add_evasion\shas_network_drive.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string20 = /.{0,1000}add_evasion\shas_public_desktop.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string21 = /.{0,1000}add_evasion\shas_recent_files.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string22 = /.{0,1000}add_evasion\shas_recycle_bin.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string23 = /.{0,1000}add_evasion\shas_username\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string24 = /.{0,1000}add_evasion\shas_vm_mac.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string25 = /.{0,1000}add_evasion\shas_vm_regkey.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string26 = /.{0,1000}add_evasion\shide_console.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string27 = /.{0,1000}add_evasion\sinteraction_getchar.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string28 = /.{0,1000}add_evasion\sinteraction_system_pause.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string29 = /.{0,1000}add_evasion\sis_debugger_present.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string30 = /.{0,1000}add_evasion\ssleep_by_ping\s.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string31 = /.{0,1000}avet\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string32 = /.{0,1000}build_40xshikata_revhttpsunstaged_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string33 = /.{0,1000}build_50xshikata_quiet_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string34 = /.{0,1000}build_50xshikata_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string35 = /.{0,1000}build_asciimsf_fromcmd_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string36 = /.{0,1000}build_asciimsf_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string37 = /.{0,1000}build_avetenc_dynamicfromfile_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string38 = /.{0,1000}build_avetenc_fopen_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string39 = /.{0,1000}build_avetenc_mtrprtrxor_revhttps_win64\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string40 = /.{0,1000}build_calcfromcmd_50xshikata_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string41 = /.{0,1000}build_calcfrompowersh_50xshikata_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string42 = /.{0,1000}build_checkdomain_rc4_mimikatz\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string43 = /.{0,1000}build_disablewindefpsh_xorfromcmd_revhttps_win64\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string44 = /.{0,1000}build_dkmc_downloadexecshc_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string45 = /.{0,1000}build_downloadbitsadmin_mtrprtrxor_revhttps_win64\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string46 = /.{0,1000}build_downloadbitsadmin_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string47 = /.{0,1000}build_downloadcertutil_revhttps_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string48 = /.{0,1000}build_downloadcurl_mtrprtrxor_revhttps_win64\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string49 = /.{0,1000}build_sleep_rc4_mimikatz\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string50 = /.{0,1000}build_svc_20xshikata_bindtcp_win32\.sh.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string51 = /.{0,1000}encode_payload\src4\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string52 = /.{0,1000}evasion\/has_recycle_bin\..{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string53 = /.{0,1000}govolution\/avet.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string54 = /.{0,1000}input\/shellcode_enc_raw\.txt.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string55 = /.{0,1000}input\/shellcode_raw\.txt.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string56 = /.{0,1000}pe2shc\.exe.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string57 = /.{0,1000}pe2shc_.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string58 = /.{0,1000}set_command_exec\sexec_via_cmd.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string59 = /.{0,1000}set_command_exec\sexec_via_powershell.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string60 = /.{0,1000}set_command_exec\sno_command.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string61 = /.{0,1000}set_command_source\sdownload_bitsadmin.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string62 = /.{0,1000}set_decoder\sxor.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string63 = /.{0,1000}set_payload_execution_method\sexec_shellcode64.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string64 = /.{0,1000}set_payload_execution_method\sinject_dll.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string65 = /.{0,1000}set_payload_info_source\sfrom_command_line_raw.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string66 = /.{0,1000}set_payload_source\sdownload_powershell.{0,1000}/ nocase ascii wide
        // Description: AVET is an AntiVirus Evasion Tool. which was developed for making life easier for pentesters and for experimenting with antivirus evasion techniques. as well as other methods used by malicious software. For an overview of new features in v2.3. as well as past version increments. have a look at the CHANGELOG file.
        // Reference: https://github.com/govolution/avet
        $string67 = /.{0,1000}source\/avetsvc\.c.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
