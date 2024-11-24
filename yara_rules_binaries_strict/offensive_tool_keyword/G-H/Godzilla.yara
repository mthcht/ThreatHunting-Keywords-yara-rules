rule Godzilla
{
    meta:
        description = "Detection patterns for the tool 'Godzilla' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Godzilla"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string1 = /\s\-\-single\-argument\shttps\:\/\/github\.com\/BeichenDream\/Godzilla/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string2 = /\/BadPotato\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string3 = /\/GodzillaSource\.git/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string4 = /\/Meterpreter\.classs/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string5 = /\/meterpreter\.php/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string6 = /\/releases\/download\/v4\.0\.1\-godzilla\/godzilla\.jar/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string7 = /\/RevlCmd\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string8 = /\/SafetyKatz\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string9 = /\/SharpWeb\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string10 = /\/SweetPotato\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string11 = /\\BadPotato\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string12 = /\\meterpreter\.php/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string13 = /\\meterpreterTip\.txt/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string14 = /\\meterpreterTip2\.txt/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string15 = /\\reverse64\.bin/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string16 = /\\RevlCmd\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string17 = /\\SafetyKatz\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string18 = /\\SharpWeb\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string19 = /\\SweetPotato\.dll/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string20 = "241aa661189fa38aa2519055d8145944658c9234282a3dee30ab625eba575464" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string21 = "314bf9a5bd1f5d13c2dbc28f52e22e401c5216ad5071e5bf46de4b93d882c72f" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string22 = "31a743113d28136e8facd24ed8fac8bb73fdf70a07a4451bb6aff3b2e648fd38" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string23 = "5475aec3b9837b514367c89d8362a9d524bfa02e75b85b401025588839a40bcb" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string24 = "62b7eff31d339fd04e6d39aba47b5f37b1b6feb27f85c3c71e4d2d600e8142c6" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string25 = "7026d773b575627e0e811e1027f8959ab9a596c9e9157359c9cd69be1328bac4" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string26 = "734c3a8ec0d442a49c7909702012c50ab2db32cfed02e82b5c19a5afda5a87d3" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string27 = "75574959bbdad4b4ac7b16906cd8f1fd855d2a7df8e63905ab18540e2d6f1600" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string28 = "808Mak1r/GodzillaSource" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string29 = "85e3e5dbf52f38be79b8ddf3f0de3ae1250584fde316728b96be26b697f36df0" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string30 = "88184fc856b37ace040097bb476e71a445f8ef1ac3e66b6bcac98f29bb5bf64e" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string31 = "89a0c5bfa07f8c0114208173eb77b9a49a43cee5694c5111dd178ea0b51c51f0" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string32 = "8ab8e1d302f81af6f3c240642489b297c549de98a7e46c8436cba750bf288b51" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string33 = "8c3c68f026da1de92c0162f38b509ee335041b7cf5f861fce1d38b053287c866" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string34 = "a44a5e8e65266611d5845d88b43c9e4a9d84fe074fd18f48b50fb837fa6e429d" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string35 = "APP_ENV_KEY = \"AutoExecByPassOpenBasedir\"" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string36 = "b42f9571d486a8aef5b36d72c1c8fff83f29cac2f9c61aece3ad70537d49b222" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string37 = "bcaf32b547ce962291c3e905b9fe6dd2df389b19da01dedff9bd7b2bb5b71039" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string38 = "BeichenDream/Godzilla" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string39 = /beichendream\@gmail\.com/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string40 = "cd310c1827d7f9686c56b7ca259e8782a17964c23e93c932ae201f78ab046b20" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string41 = "ce310ab611895db1767877bd1f635ee3c4350d6e17ea28f8d100313f62b87382" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string42 = "d90ebaede19390d74f136a83ea5c391f1b550322295c22d5427d62c2d573c197" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string43 = "ec9204b818a8bf3893428eb9c869e8aa2d53eaac52d9cb249ede288dbf042fea" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string44 = "fd97e0ace21c435be9c5d10af9c2c04685069007614db6f46b06237beee2a458" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string45 = "Freakboy/Godzilla" nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string46 = /Godzilla\-1\.0\.jar/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string47 = /http\:\/\/127\.0\.0\.1\/shell\.jsp/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string48 = /icacls\.exe\sC\:\\ProgramData\\Oracle\\Java\\\.oracle_jre_usage\s\/grant\s\\"everyone\\"\:\(OI\)\(CI\)M/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string49 = /Meterpreter\.java/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string50 = /vip\.youwe\.shell\.core\.shell/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string51 = /vip\.youwe\.shell\.shells\.payloads\.java/ nocase ascii wide
        // Description: Webshell Manager Tool that provide request proxy, server info, RCE shell, terminal execution, memory shell, port forwarding, and MSF bind/reverse shell capabilities.
        // Reference: https://github.com/BeichenDream/Godzilla
        $string52 = /vip\.youwe\.shell\.shells\.plugins\.java/ nocase ascii wide
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
