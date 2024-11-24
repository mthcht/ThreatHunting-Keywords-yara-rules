rule Dendrobate
{
    meta:
        description = "Detection patterns for the tool 'Dendrobate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dendrobate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string1 = /\sDendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string2 = /\/Bates\.csproj/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string3 = /\/Dendrobate\.git/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string4 = /\/Dendron\.bin/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string5 = /\/Dendron\.csproj/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string6 = /\/Dendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string7 = /\/Dendron\.sln/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string8 = /\/hDendron\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string9 = /\\Dendrobate\\/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string10 = /\\Dendron\.bin/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string11 = /\\Dendron\.exe/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string12 = /\\Dendron\.sln/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string13 = /Bates\.exe\s\-\-kill/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string14 = /Bates\.exe\s\-\-listen/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string15 = "Dendrobate-master" nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string16 = /dendron.{0,100}FileMonInject\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string17 = /EasyHook\-Managed.{0,100}InjectionLoader\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string18 = /EasyHook\-Managed.{0,100}WOW64Bypass\./ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string19 = /EasyHook\-Managed\/LocalHook\.cs/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string20 = "FuzzySecurity/Dendrobate" nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string21 = /ManagedEasyHook\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string22 = /NativeEasyHook32\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string23 = /NativeEasyHook64\.dll/ nocase ascii wide
        // Description: Dendrobate is a framework that facilitates the development of payloads that hook unmanaged code through managed .NET code
        // Reference: https://github.com/FuzzySecurity/Dendrobate
        $string24 = "P8CuaPrgwBjunvZxJcgq" nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
