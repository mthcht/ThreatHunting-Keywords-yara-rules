rule spinningteacup
{
    meta:
        description = "Detection patterns for the tool 'spinningteacup' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spinningteacup"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\sspinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\svbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = "\"This is a macro obfuscating framework\"" nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\s\-\-norandomvariables\s\-\-math/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\s\-\-wordlistpath\s.{0,100}\s\-\-encodestring/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-randomcuts\s5\s10\s\-\-norandomint/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-usebusinesswords\s\-\-encodestring_calls/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\.py\s.{0,100}\.vba\s.{0,100}\.vba\s\-\-usebusinesswords\s\-\-math/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\/spinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\/vbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\\spinningteacup\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /\\vbarandomizer\.py/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = "577b85630ecfd64d6817de11c4abf256512d299f70998c8c531202272123b202" nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = "attempt to randomize script without setting all randomizations methods" nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /from\srandomizers\.vbarandomizer\simport\svbaRandomizer/ nocase ascii wide
        // Description: identify different parts of a vba script and perform substitutions
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = "your script has been obfuscated and output to " nocase ascii wide
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
