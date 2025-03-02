rule ADCSCoercePotato
{
    meta:
        description = "Detection patterns for the tool 'ADCSCoercePotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSCoercePotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string1 = /\.asp\s\-\-adcs\s\-\-template\sMachine\s\-smb2support/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string2 = /\/ADCSCoercePotato\.git/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string3 = "/ADCSCoercePotato/" nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string4 = /\[\!\]\sCouldn\'t\scommunicate\swith\sthe\sfake\sRPC\sServer/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string5 = /\[\+\]\sGot\sNTLM\stype\s3\sAUTH\smessage\sfrom\s.{0,100}\swith\shostname\s/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string6 = /\\ADCSCoercePotato\\/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string7 = /\\MSFRottenPotato\.h/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string8 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string9 = /ADCSCoercePotato\.cpp/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string10 = /ADCSCoercePotato\.exe/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string11 = /ADCSCoercePotato\.sln/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string12 = /ADCSCoercePotato\.vcxproj/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string13 = /ADCSCoercePotato\\n\-\s\@decoder_it\s2024\\/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string14 = "decoder-it/ADCSCoercePotato" nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string15 = /include\s\\"MSFRottenPotato\.h\\"/ nocase ascii wide
        // Description: coercing machine authentication but specific for ADCS server
        // Reference: https://github.com/decoder-it/ADCSCoercePotato
        $string16 = "int PotatoAPI::findNTLMBytes" nocase ascii wide
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
