rule echo
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string1 = /\%COMSPEC\%.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string2 = /cmd.{0,100}echo.{0,100}\\pipe\\/ nocase ascii wide
        // Description: Adversaries may attempt to test echo command after exploitation
        // Reference: N/A
        $string3 = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,100}\secho\s123/ nocase ascii wide
        // Description: alternative to whoami
        // Reference: N/A
        $string4 = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
        // Description: potential malleable Cobalt Strike profiles behavior
        // Reference: https://github.com/IcebreakerSecurity/DelegationBOF
        $string5 = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: Named pipe impersonation
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string6 = /cmd\.exe\s\/c\secho\s.{0,100}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string7 = /echo\s\'\'\'\'\s\-\/\.bash\shistory/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string8 = /echo\s\'\'\s\>\s\~\/\.bash_history/ nocase ascii wide
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string9 = /echo\s\\"\\"\s\>\s\/var\/log\/auth\.log\s/ nocase ascii wide
        // Description: This command disables kprobes by writing '0' to the enabled file. Kprobes are dynamic breakpoints in the Linux kernel that can be used to intercept functions and gather information for debugging or monitoring.
        // Reference: N/A
        $string10 = /echo\s0\s\>\s\/sys\/kernel\/debug\/kprobes\/enabled/ nocase ascii wide
        // Description: This command turns off tracing for a specific instance
        // Reference: N/A
        $string11 = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,100}\/tracing_on/ nocase ascii wide
        // Description: linux command abused by attacker
        // Reference: N/A
        $string12 = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/ nocase ascii wide
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
