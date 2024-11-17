rule FileZilla
{
    meta:
        description = "Detection patterns for the tool 'FileZilla' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FileZilla"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string1 = /\/FileZilla_.{0,100}_sponsored\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string2 = /\/FileZilla_Server_.{0,100}\.deb/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string3 = /\\FileZilla_.{0,100}_sponsored\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string4 = /\\FILEZILLA_.{0,100}_WIN64_SPONSO\-.{0,100}\.pf/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string5 = /\\FileZilla_.{0,100}\-setup\.exe/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string6 = /\\FileZilla_Server_/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string7 = /\\Program\sFiles\\FileZilla\sFTP\sClient\\/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string8 = /\\Program\sFiles\\FileZilla\sServer/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string9 = /\\Software\\WOW6432Node\\FileZilla\sClient/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string10 = /\>FileZilla\sFTP\sClient\</ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string11 = /\>FileZilla\sServer\</ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string12 = /download\.filezilla\-project\.org/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string13 = /Software\\FileZilla/ nocase ascii wide
        // Description: FileZilla admintool used by threat actors for persistence and data exfiltration
        // Reference: https://filezilla-project.org/
        $string14 = /Win32\/FileZilla_BundleInstaller/ nocase ascii wide
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
