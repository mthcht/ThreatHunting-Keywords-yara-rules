rule Villain
{
    meta:
        description = "Detection patterns for the tool 'Villain' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Villain"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string1 = " --file-smuggler-port " nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string2 = " --hoax-port " nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string3 = " --netcat-port " nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string4 = /\.villain_core/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string5 = /\/hoaxshell\/.{0,100}\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string6 = "/t3l3machus/Villain" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string7 = /\\hoaxshell\\.{0,100}\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string8 = /awk_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string9 = /bash_read_line_reverse_tcp\.py/
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string10 = "cmdinspector OFF" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string11 = "cmdinspector ON" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string12 = "conptyshell " nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string13 = "eRv6yTYhShell" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string14 = "File_Smuggler_Http_Handler" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string15 = "generate payload=" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string16 = "Invoke-ConPtyShell" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string17 = "list_backdoors" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string18 = "obfuscate_cmdlet" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string19 = /perl_no_sh_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string20 = /php_passthru_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string21 = /php_popen_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string22 = /php_proc_open_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string23 = /powershell_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string24 = /powershell_reverse_tcp_v2\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string25 = "proxy_cmd_for_exec_by_sibling" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string26 = /python3_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string27 = /python3_reverse_tcp_v2\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string28 = /ruby_no_sh_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string29 = /ruby_reverse_tcp\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string30 = "SpawneRv6yTYhShell" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string31 = /Villain\.git/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string32 = /villain\.py/ nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string33 = "Villain/Core" nocase ascii wide
        // Description: Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells. enhance their functionality with additional features (commands. utilities etc) and share them among connected sibling servers (Villain instances running on different machines).
        // Reference: https://github.com/t3l3machus/Villain
        $string34 = /villain_core\.py/ nocase ascii wide
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
