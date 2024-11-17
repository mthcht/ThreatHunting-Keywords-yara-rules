rule Dirty_Vanity
{
    meta:
        description = "Detection patterns for the tool 'Dirty-Vanity' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dirty-Vanity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string1 = /\#include\s\\"DirtyVanity\.h\\"/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string2 = /\/Dirty\-Vanity\.git/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string3 = /\/k\smsg\s.{0,100}\sHello\sfrom\sDirty\sVanity/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string4 = /\/k\smsg\s.{0,100}\sHello\sfrom\sTam\.Men/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string5 = /\/vanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string6 = /\[\+\]\sNo\sPID\sprovided\,\screating\sa\snew\scalc\.exe\sprocess\sand\susing\sits\sPID/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string7 = /\[\+\]\sSuccesfuly\swrote\sshellcode\sto\svictim\.\sabout\sto\sstart\sthe\sMirroring/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string8 = /\[\+\]\sUSAGE\:\sDirtyVanity\s/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string9 = /\\DirtyVanity\.cpp/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string10 = /\\DirtyVanity\.sln/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string11 = /\\vanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string12 = /2C809982\-78A1\-4F1C\-B0E8\-C957C93B242F/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string13 = /2d837b6c7343aec8123077db07d3fb8f9f7e44c5b108bf713380b17dac7569b9/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string14 = /53891DF6\-3F6D\-DE4B\-A8CD\-D89E94D0C8CD/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string15 = /deepinstinct\/Dirty\-Vanity/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string16 = /DirtyVanity\.exe/ nocase ascii wide
        // Description: injection technique abusing windows fork API to evade EDRs
        // Reference: https://github.com/deepinstinct/Dirty-Vanity
        $string17 = /e977ee0a5a2f0063f34b0b744b0753e65990e9467843b0dec3c281a6d4a2e009/ nocase ascii wide
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
