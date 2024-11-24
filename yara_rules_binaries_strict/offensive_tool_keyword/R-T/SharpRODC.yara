rule SharpRODC
{
    meta:
        description = "Detection patterns for the tool 'SharpRODC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRODC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string1 = /\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sRODC\s\{count\}\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\s/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string2 = /\/SharpRODC\.git/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string3 = /\\SharpRODC\./ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string4 = /\\SharpRODC\\/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string5 = "62e779d3d44b32644b427335bb091880b637ed5dd3c01ec2ecd9c732a5d17539" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string6 = "69e92737993cca7f4757a5a3dc027b1f85ee6d836f18f6433332d9d269b9262f" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string7 = "987ebc109f9bb594b780a59dbe5f5b5c3694f5ac21bb0bd044b4e06ccb64bdab" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string8 = "9ca9d965d2d159763c2ca4431a1fa6597ca6633f443732139340341c77f6a39f" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string9 = "D305F8A3-019A-4CDF-909C-069D5B483613" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string10 = "Get-ADComputer RODC -Properties msDS-RevealedList" nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string11 = /https\:\/\/whoamianony\.top\/posts\// nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string12 = /Set\-DomainObject\s\-Identity\s\'CN\=Allowed\sRODC\sPassword\sReplication\sGroup.{0,100}\s\-Set\s\@\{\'member\'\=\@\(/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string13 = /Set\-DomainObject\s\-Identity\s\'CN\=Denied\sRODC\sPassword\sReplication\sGroup.{0,100}\s\-Clear\s\'member\'/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string14 = /Set\-DomainObject\s\-Identity\s\'CN\=RODC.{0,100}\s\-Set\s\@\{\'msDS\-NeverRevealGroup\'\=\@\(/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string15 = /SharpRODC\.exe/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string16 = /SharpRODC\.pdb/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string17 = "wh0amitz/SharpRODC" nocase ascii wide
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
