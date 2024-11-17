rule Keethief
{
    meta:
        description = "Detection patterns for the tool 'Keethief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Keethief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string1 = /\sKeeThief\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string2 = /\$KeePassXMLPath\sbackdoored/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string3 = /\$KeePassXMLPath\striggers\sremoved/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string4 = /\/KeeTheft\.exe/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string5 = /\/KeeThief\.git/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string6 = /\/KeeThief\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string7 = /\\Get\-FunctionHash\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string8 = /\\Get\-PEHeader\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string9 = /\\Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string10 = /\\KeePass\.sln/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string11 = /\\KeeTheft\.config/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string12 = /\\KeeTheft\.exe/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string13 = /\\KeeTheft\.INI/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string14 = /\\KeeThief\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string15 = /\\MostPopularPasswords\.txt/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string16 = /\>KeeTheft\</ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string17 = /211446645fa7a934da99f218cc049cd1c59c68ac2a5da2033eaceff80b1d1c0e/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string18 = /3d00518d63ef9b656fdef85621d8a4f3137569ea71b07d431da6b39704f54dee/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string19 = /3FCA8012\-3BAD\-41E4\-91F4\-534AA9A44F96/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string20 = /457cd41fbb528812aa51bc4b31fce042cdf736281b162181d91c47733d0e9e4b/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string21 = /4969b09ab7cae1ba1f02a509b9b7099195fab22321b73039fcce92e9974d7b93/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string22 = /6FC09BDB\-365F\-4691\-BBD9\-CB7F69C9527A/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string23 = /80BA63A4\-7D41\-40E9\-A722\-6DD58B28BF7E/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string24 = /935D33C5\-62F1\-40FE\-8DB0\-46B6E01342FB/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string25 = /a01a3fe8fd6c3ff03908efd3321438df49365d0f64fa0a862419e31112936e3e/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string26 = /adbed7685fc512f48cf0edb1eb0df16fed97c52d5eab0fe70e88286c47d53e3d/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string27 = /Add\-KeePassConfigTrigger\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string28 = /Add\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string29 = /b0cf4ccee3c06fe7d3c7ff2afbfefbe972f82008ec5b2f8a5e5d5cb9a58861a2/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string30 = /c0fdcce36afa206ce080c1b8602ecf18fdc23a207078cb437594d7f674b2a693/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string31 = /C23B51C4\-2475\-4FC6\-9B3A\-27D0A2B99B0F/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string32 = /Could\snot\sfind\saddress\smarker\sin\sshellcode/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string33 = /dbed4217e61d4deba7cfb5aa97aef6687507d9bd990110cc31b0d35ee32acada/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string34 = /EA92F1E6\-3F34\-48F8\-8B0A\-F2BBC19220EF/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string35 = /Error\:\sCould\snot\screate\sa\sthread\sfor\sthe\sshellcode/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string36 = /Find\-KeePassconfig\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string37 = /Find\-KeePassconfig/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string38 = /function\sLocal\:Inject\-RemoteShellcode\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string39 = /GetKcpPasswordInfo/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string40 = /Get\-KeePassConfigTrigger\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string41 = /Get\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string42 = /Get\-KeePassDatabaseKey\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string43 = /Get\-KeePassDatabaseKey/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string44 = /Get\-PEHeader\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string45 = /GhostPack\/KeeThief/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string46 = /Injecting\sshellcode\sinto\sPID\:\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string47 = /Injecting\sshellcode\sinto\sPowerShell/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string48 = /Interesting\?\sthere\sare\smultiple\s\.NET\sruntimes\sloaded\sin\sKeePass/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string49 = /Invoke\-Shellcode\s\-ProcessId\s/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string50 = /KcpPassword\.cs/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string51 = /KeePassConfig\.ps1/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string52 = /KeePassLib\.Keys\.KcpPassword/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string53 = /KeeThief/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string54 = /MSIL\/KeeThief\.A\!tr\.pws/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string55 = /MSIL\/PSW\.KeeThief\.A/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string56 = /ReleaseKeePass\.exe/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string57 = /ReleaseKeeTheft\.exe/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string58 = /Remove\-KeePassConfigTrigger/ nocase ascii wide
        // Description: Allows for the extraction of KeePass 2.X key material from memory as well as the backdooring and enumeration of the KeePass trigger system.
        // Reference: https://github.com/GhostPack/KeeThief
        $string59 = /Spyware\.KeeThief/ nocase ascii wide
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
