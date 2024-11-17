rule SirepRAT
{
    meta:
        description = "Detection patterns for the tool 'SirepRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirepRAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string1 = /\s\-\-return_output\s\-\-as_logged_on_user\s\-\-cmd\s/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string2 = /\sSirepRAT\.py/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string3 = /\/Sirep_Command_Payload\.bt/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string4 = /\/SirepRAT\.git/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string5 = /\/SirepRAT\.py/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string6 = /\/SirepRAT\/releases\// nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string7 = /\\Sirep_Command_Payload\.bt/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string8 = /\\SirepRAT\.py/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string9 = /\\SirepRAT\\/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string10 = /\\SirepRAT\-2\.0\.0\\/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string11 = /\\SirepRAT\-master/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string12 = /\\Windows\\System32\\uploaded\.txt/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string13 = /029fa62f9ee4ffbf98d5b187c658db8ecff38ccdc4dc5a8c37890446a33d1a23/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string14 = /4156a612622946b1daab4b43c632edf80477c45f2bbf55f474ffc33c1cd077f2/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string15 = /845e930b1479640235d571dceb63d0b3df3f807ab09eb0f53159b043a2e20e23/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string16 = /b718b5c185eb16e7276da28a376095a99f45007a953080ad759d3c839d0c520f/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string17 = /c9152451df19ff8cac70faf169055ea18b3b91eb105d722873b27da26af7b599/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string18 = /f463d3fbb08ed690d8d2429874bf6d36d9ac0d8e74a06439586fb4f49cbe8eac/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string19 = /fb785781e1e83a00582d1d3348c70249c256db03ddc4513f5b1a0853949b76ba/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string20 = /from\s\.SirepCommand\simport\sSirepCommand/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string21 = /from\s\.SirepResult\simport\sSirepResult/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string22 = /SafeBreach\-Labs\/SirepRAT/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string23 = /Sending\sSirep\spayload/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string24 = /SirepRAT\.py\s/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string25 = /SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_Slides\.pdf/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string26 = /SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_White_Paper\.pdf/ nocase ascii wide
        // Description: RAT tool - Remote Command Execution as SYSTEM on Windows IoT Core
        // Reference: https://github.com/SafeBreach-Labs/SirepRAT
        $string27 = /SirepRAT\-2\.0\.0\.zip/ nocase ascii wide
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
