rule havoc
{
    meta:
        description = "Detection patterns for the tool 'havoc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "havoc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string1 = /\sdemon\.x64\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string2 = " havoc-client" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string3 = /\.\/donut\s.{0,100}\.exe/
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string4 = /\.\/Havoc/
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string5 = /\.\/havoc\s/
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string6 = "/Cracked5pider/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string7 = /\/demon\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string8 = /\/demon\.x64\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string9 = /\/demon1\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string10 = /\/demosyscalls\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string11 = /\/Dialogs\/Payload\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string12 = /\/Havoc\.cpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string13 = /\/Havoc\.qss/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string14 = /\/Havoc\.rc/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string15 = "/Havoc/data/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string16 = "/Havoc/main/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string17 = "/HavocFramework/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string18 = "/HavocImages/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string19 = "/havoc-py/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string20 = /\/implants\/.{0,100}\/Syscalls\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string21 = "/Jump-exec/Psexec" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string22 = /\/kerberoast\.c/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string23 = /\/kerberoast\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string24 = /\/nanodump\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string25 = "/payloads/DllLdr/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string26 = /\/RemoteOps\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string27 = /\/scshell\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string28 = /\/Talon\.py/
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string29 = /\/Talon\/.{0,100}Agent\/Source/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string30 = /\/Widgets\/LootWidget\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string31 = /\/WMI\/wmi\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string32 = /\\demon\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string33 = /\\demon\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string34 = /\\demon\.x64\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string35 = /\\demon1\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string36 = /\\demosyscalls\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string37 = /\\Ekko\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string38 = "40056/service-endpoint" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string39 = "5spider:password1234" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string40 = /bin\/addusertogroup\.x64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string41 = /bin\/setuserpass\.x64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string42 = /Delegation\/delegation\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string43 = /DllLdr\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string44 = /Domaininfo\/Domaininfo\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string45 = "dotnet inline-execute " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string46 = /externalc2\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string47 = "f5a45c4aa478a7ba9b44654a929bddc2f6453cd8d6f37cd893dda47220ad9870" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string48 = "havoc client" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string49 = "havoc server" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string50 = /havoc\.agent/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string51 = /Havoc\.git/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string52 = /Havoc\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string53 = /havoc\.service/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string54 = /havoc\.yaotl/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string55 = "Havoc/Client" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string56 = "Havoc/cmd/" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string57 = "Havoc/payloads" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string58 = "Havoc/pkg" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string59 = "Havoc/Teamserver" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string60 = /havoc_agent\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string61 = /havoc_agent_talon\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string62 = /havoc_default\.yaotl/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string63 = "havoc_externalc2" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string64 = "havoc_service_connect" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string65 = "havoc-c2-client" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string66 = "havoc-c2-data" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string67 = /havocframework\.com/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string68 = "HavocService" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string69 = "HavocTalonInteract" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string70 = /HavocUi\.cpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string71 = /HavocUi\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string72 = /HavocUI\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string73 = /http.{0,100}\/demon\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string74 = /http.{0,100}\/demon\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string75 = /implant\.sleep\-obf/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string76 = /Implant\\SleepMask/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string77 = "inject 1337 /" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string78 = /inject\.spawn/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string79 = /inject\.spoofaddr/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string80 = /Injection\\Spawn32/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string81 = /Injection\\Spawn64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string82 = /InvokeAssembly\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string83 = "jump-exec psexec " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string84 = /nanodump_ppl\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string85 = /nanodump_ssp\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string86 = /nanorobeus\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string87 = /powerpick\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string88 = /PowerPick\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string89 = /PowershellRunner\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string90 = /profiles\/havoc\.yaotl/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string91 = /ServiceHavoc\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string92 = "set havoc " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string93 = "shellcode inject " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string94 = "shellcode spawn " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string95 = /Shellcode\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string96 = "token find-tokens" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string97 = "token impersonate " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string98 = "token privs-get" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string99 = "token privs-list" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string100 = "token steal " nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string101 = "x-ishavocframework" nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string102 = "dcenum " nocase ascii wide
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
