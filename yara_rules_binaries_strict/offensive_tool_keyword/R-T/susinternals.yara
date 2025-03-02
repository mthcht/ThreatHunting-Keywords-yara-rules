rule susinternals
{
    meta:
        description = "Detection patterns for the tool 'susinternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "susinternals"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string1 = /\spsexecsvc\.py/ nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string2 = /PSEXECSVC19\=b64decode\(/ nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string3 = /\/psexecsvc\.py/ nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string4 = /\\psexecsvc\.py/ nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string5 = "fcb2f607771f185531790722ac8e3a924146186bbd3d9e03a7a793545772bdf2" nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string6 = "PSExecSVC remote orchestrator" nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string7 = "Received version from PSEXECSVC: " nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string8 = "Sending init packet to PSEXECSVC" nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string9 = "Sending PSExecSVC version 190 " nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string10 = "sensepost/susinternals" nocase ascii wide
        // Description: python implementation of PSExec native service implementation
        // Reference: https://github.com/sensepost/susinternals
        $string11 = "VqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAByxaEKNqTPWTakz1k2pM9ZP9xLWRGkz1k/3FpZJqTPWT/cXFkhpM9ZNqTOWeikz1k/3ExZs6TPWT/cW1k3pM9ZP9xeWTekz1lSaWNoNqTPWQAAAAAAAAAAUEUAAEwBBAA8EQBSAAAAAAAAAADgAAMBCwEJAAAcAg" nocase ascii wide
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
