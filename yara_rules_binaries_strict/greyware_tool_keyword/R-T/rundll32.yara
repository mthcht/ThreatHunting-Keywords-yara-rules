rule rundll32
{
    meta:
        description = "Detection patterns for the tool 'rundll32' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rundll32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Caling MiniDump function - dump memory of a process (often abused to dump lsass process)
        // Reference: N/A
        $string1 = /comsvcs\.dll\,\sMiniDump\s/ nocase ascii wide
        // Description: Calling MiniDump export by ordinal - dump memory of a process (often abused to dump lsass process
        // Reference: N/A
        $string2 = /comsvcs\.dll\,\#24\s/ nocase ascii wide
        // Description: dumping lsass
        // Reference: N/A
        $string3 = /lsass.{0,100}rundll32\.exe\s.{0,100}comsvcs\.dll\,\sMiniDump\s.{0,100}\.dmp\sfull/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string4 = /rundll32.{0,100}\.dll.{0,100}a.{0,100}\/p\:/ nocase ascii wide
        // Description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
        // Reference: https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence
        $string5 = /rundll32.{0,100}\.dll.{0,100}StartW/ nocase ascii wide
        // Description: Caling MiniDump function - dump memory of a process (often abused to dump lsass process)
        // Reference: N/A
        $string6 = /rundll32.{0,100}comsvcs\.dll\sMiniDump\s/ nocase ascii wide
        // Description: dumping lsass
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string7 = /rundll32\.exe\s.{0,100}comsvcs\.dll\,\sMiniDump\s.{0,100}lsass.{0,100}full/ nocase ascii wide
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
