rule sudo
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: sudo on windows allowing privilege escalation
        // Reference: https://www.tiraniddo.dev/2024/02/sudo-on-windows-quick-rundown.html
        $string1 = /\.server_DoElevationRequest\(\(Get\-NtProcess\s\-ProcessId\s\$pid\).{0,100}\\"cmd\.exe\\".{0,100}C\:\\\\"/ nocase ascii wide
        // Description: sudo on windows allowing privilege escalation
        // Reference: https://www.tiraniddo.dev/2024/02/sudo-on-windows-quick-rundown.html
        $string2 = /Connect\-RpcClient\s.{0,100}\s\-EndpointPath\ssudo_elevate_4652/ nocase ascii wide
        // Description: Sudo Persistence via sudoers file
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /echo\s.{0,100}\%sudo\s\sALL\=\(ALL\)\sNOPASSWD\:\sALL.{0,100}\s\>\>\s\/etc\/sudoers/ nocase ascii wide
        // Description: access sensitive files by abusing sudo permissions
        // Reference: N/A
        $string4 = /sudo\sapache2\s\-f\s\/etc\/shadow/ nocase ascii wide
        // Description: abusing LD_LIBRARY_PATH sudo option  to escalade privilege
        // Reference: N/A
        $string5 = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/ nocase ascii wide
        // Description: abusinf LD_PREDLOAD option to escalade privilege
        // Reference: N/A
        $string6 = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
