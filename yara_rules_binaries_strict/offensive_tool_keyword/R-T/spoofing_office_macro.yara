rule spoofing_office_macro
{
    meta:
        description = "Detection patterns for the tool 'spoofing-office-macro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoofing-office-macro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string1 = /\/spoofing\-office\-macro\.git/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string2 = /\\macro64\.vba/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string3 = /\\spoofing\-office\-macro\-master/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string4 = /8b4cb728e2db083daf0b42a3d3e6982e161ba42f90264e6da1508800e4b4d394/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string5 = /christophetd\/spoofing\-office\-macro/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string6 = /http\:\/\/bit\.ly\/2TxpA4h/ nocase ascii wide
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
