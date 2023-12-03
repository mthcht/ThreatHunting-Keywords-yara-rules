rule AlanFramework
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string1 = /.{0,1000}\/alan\.log.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string2 = /.{0,1000}\/Alan\.v.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string3 = /.{0,1000}\\agent_exe\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string4 = /.{0,1000}\\alan\.log.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string5 = /.{0,1000}\\Alan\.v.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string6 = /.{0,1000}\\asm\\x64\\alter_pe_sections.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string7 = /.{0,1000}\\asm\\x86\\alter_pe_sections.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string8 = /.{0,1000}\\ES\.Alan\.Core.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string9 = /.{0,1000}agent\/cmd_download_files\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string10 = /.{0,1000}agent\/cmd_exec\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string11 = /.{0,1000}agent\/cmd_kill\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string12 = /.{0,1000}agent\/cmd_proxy\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string13 = /.{0,1000}agent\/cmd_run\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string14 = /.{0,1000}agent\/cmd_shell\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string15 = /.{0,1000}agent\/cmd_sleep\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string16 = /.{0,1000}agent\/cmd_sysinfo\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string17 = /.{0,1000}agent\/cmd_upload_files\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string18 = /.{0,1000}agent\\cmd_download_files\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string19 = /.{0,1000}agent\\cmd_exec\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string20 = /.{0,1000}agent\\cmd_kill\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string21 = /.{0,1000}agent\\cmd_proxy\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string22 = /.{0,1000}agent\\cmd_run\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string23 = /.{0,1000}agent\\cmd_shell\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string24 = /.{0,1000}agent\\cmd_sleep\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string25 = /.{0,1000}agent\\cmd_sysinfo\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string26 = /.{0,1000}agent\\cmd_upload_files\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string27 = /.{0,1000}agent_dll\.dll.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string28 = /.{0,1000}AlanFramework\.git.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string29 = /.{0,1000}c:\\agent\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string30 = /.{0,1000}dotnet\s\.\/Server\.dll.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string31 = /.{0,1000}DownloadString.{0,1000}https:\/\/checkip\.amazonaws\.com.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string32 = /.{0,1000}dump_lsass\.js.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string33 = /.{0,1000}dump_process\(.{0,1000}lsass\.exe.{0,1000}\).{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string34 = /.{0,1000}enkomio\/AlanFramework.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string35 = /.{0,1000}ES\.Alan\.Core\/.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string36 = /.{0,1000}http.{0,1000}:\/\/127\.0\.0\.1:4433.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string37 = /.{0,1000}http.{0,1000}:\/\/127\.0\.0\.1:5556.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string38 = /.{0,1000}http.{0,1000}:\/\/localhost:4433.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string39 = /.{0,1000}http.{0,1000}:\/\/localhost:5556.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string40 = /.{0,1000}pe_packer\/dll_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string41 = /.{0,1000}pe_packer\/exe_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string42 = /.{0,1000}pe_packer\/main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string43 = /.{0,1000}pe_packer\\dll_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string44 = /.{0,1000}pe_packer\\exe_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string45 = /.{0,1000}pe_packer\\main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string46 = /.{0,1000}pe_packer_exe\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string47 = /.{0,1000}powershell_command_x64\.ps1.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string48 = /.{0,1000}powershell_command_x86\.ps1.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string49 = /.{0,1000}socks5_exe\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string50 = /.{0,1000}stagerx64\.bin.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string51 = /.{0,1000}test_nanodump_exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string52 = /.{0,1000}windows_agent\/asm\/x64\/alter_pe_sections.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string53 = /.{0,1000}windows_agent\/asm\/x86\/alter_pe_sections.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string54 = /.{0,1000}windows_agent\/dll_main\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string55 = /.{0,1000}windows_agent\/exe_main\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string56 = /.{0,1000}windows_agent\/win_.{0,1000}\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string57 = /.{0,1000}windows_agent\/win_named_pipe\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string58 = /.{0,1000}windows_agent\/win_shell\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string59 = /.{0,1000}windows_console_interceptor.{0,1000}dll_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string60 = /.{0,1000}windows_console_interceptor.{0,1000}exe_main\.c.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string61 = /.{0,1000}windows_console_interceptor.{0,1000}interceptor\..{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string62 = /.{0,1000}x64PELoader\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string63 = /.{0,1000}x86PELoader\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string64 = /.{0,1000}x86PELoader\/test_agent_dll.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string65 = /.{0,1000}x86PELoader\/test_agent_exe.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string66 = /.{0,1000}x86PELoader\/test_proxy_dll.{0,1000}/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string67 = /.{0,1000}x86PELoader\/test_proxy_exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
