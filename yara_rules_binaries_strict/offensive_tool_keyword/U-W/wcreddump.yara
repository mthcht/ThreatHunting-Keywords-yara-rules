rule wcreddump
{
    meta:
        description = "Detection patterns for the tool 'wcreddump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wcreddump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string1 = " install samdump2"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string2 = /\swcreddump\s\(windows\scredentials\sdump\)/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string3 = /\swcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string4 = /\sWINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string5 = /\/wcreddump\.git/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string6 = /\/wcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string7 = /\/WINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string8 = /\\wcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string9 = /\\WINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string10 = "0d33356f9addc458bf9fc3861d9cafef954a51b66412b1cfc435eede351733f1"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string11 = "samdump2 SYSTEM SAM"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string12 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string13 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string14 = /succesfully\sdumped\sWINHELLO\spin\.s\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string15 = "truerustyy/wcreddump"
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
