rule covenant
{
    meta:
        description = "Detection patterns for the tool 'covenant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "covenant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string1 = " --name covenant " nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string2 = " start covenant" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string3 = " stop covenant" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string4 = "/Brute/BruteStager" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string5 = /\/BruteStager\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string6 = /\/Covenant.{0,100}\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string7 = /\/Covenant\.git/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string8 = "/Covenant/" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string9 = "/CovenantUsers/" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string10 = /\/GruntHTTP\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string11 = /\/Models\/PowerShellLauncher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string12 = /\/Models\/Regsvr32Launcher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string13 = /\/Models\/ShellCodeLauncher\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string14 = "/opt/Covenant/Covenant/"
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string15 = "/SharpDump" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string16 = "/SharpSploit" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string17 = /\/WhoAmI\.task/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string18 = /\\Elite\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string19 = /\\Elite\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string20 = /Brute\/Brute\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string21 = /Brute\/Brute\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string22 = /Brute\/Brute\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string23 = /BruteStager\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string24 = /BruteStager\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string25 = /CapturedCredential\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string26 = /CapturedCredential\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string27 = /CapturedHashCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string28 = /CapturedPasswordCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string29 = /CapturedTicketCredential\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string30 = "cobbr/Covenant" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string31 = "cobbr/Elite" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string32 = /Covenant\.API/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string33 = /Covenant\.csproj/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string34 = /Covenant\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string35 = /Covenant\.Models/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string36 = /Covenant\.sln/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string37 = "Covenant/Covenant" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string38 = "Covenant/wwwroot" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string39 = /CovenantAPI\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string40 = /CovenantAPIExtensions\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string41 = /CovenantBaseMenuItem\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string42 = /CovenantService\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string43 = /CovenantUser\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string44 = /CovenantUserLogin\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string45 = /CovenantUserLoginResult\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string46 = /CovenantUserRegister\./ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string47 = /docker\s.{0,100}\scovenant/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string48 = /docker\s.{0,100}\s\-\-name\selite\s/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string49 = /docker\s.{0,100}\s\-t\selite\s/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string50 = "donut-loader -" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string51 = /donut\-maker\.py\s\-/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string52 = "donut-shellcode" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string53 = /GruntInjection\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string54 = /gruntstager\.cs/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string55 = /GruntStager\.exe/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string56 = /http.{0,100}127\.0\.0\.1\:57230/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string57 = /http.{0,100}localhost\:57230/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string58 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string59 = "https://localhost:7443/" nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string60 = /obfuscate\.py\sgrunt/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string61 = /powerkatz_x64\.dll/ nocase ascii wide
        // Description: Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string62 = /powerkatz_x86\.dll/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string63 = "SharpUp audit" nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string64 = /ShellCmd\scmd\.exe\s/ nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string65 = "ShellCmd copy " nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string66 = "ShellCmd net " nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string67 = "ShellCmd sc qc " nocase ascii wide
        // Description: Covenant commands - Covenant is a collaborative .NET C2 framework for red teamers
        // Reference: https://github.com/cobbr/Covenant
        $string68 = "BypassUAC " nocase ascii wide
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
