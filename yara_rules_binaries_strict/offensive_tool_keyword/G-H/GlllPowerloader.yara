rule GlllPowerloader
{
    meta:
        description = "Detection patterns for the tool 'GlllPowerloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GlllPowerloader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string1 = /\sGlllPowerLoader\.py/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string2 = /\/APC_Injection\.cpp/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string3 = /\/GlllPowerloader\.git/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string4 = /\/GlllPowerLoader\.py/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string5 = /\[\+\]\s\\u57fa\\u4e8esyswhispers\\u7684shellcode\\u52a0\\u8f7d\\u5668/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string6 = /\[\+\]\s\\u68c0\\u6d4b\\u5230Stageless\spayload/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string7 = /\[\+\]\sGenerated\ssuccessfully\!\sa\.dll/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string8 = /\[\+\]\sGenerated\ssuccessfully\!\sa\.exe/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string9 = /\[IO\.File\]\:\:ReadAllText\(.{0,100}stubps1tovbs\.ps1/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string10 = /\\APC_Injection\.cpp/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string11 = /\\GlllPowerLoader\.py/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string12 = /\\GlllPowerLoader\-master/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string13 = /\\Ps1ToVbs\.ps1/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string14 = /\\wwwwwwwwwwwwntdll\.dll/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string15 = "54d3497f0b4197a649280a6f464d71154d7ecbcc663ab00a3805e820900a7955" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string16 = "5643f39d347a5b36f195edcd9dbba33cc3417d76ad99892a029aefa96817b41a" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string17 = "67908b4e774d138792557c430f8ec4f48aa9094b0c639bd57e7f49aacc17788e" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string18 = "88391b7725953b6c37aa40ce11c2f80894ed4216f3972bef9c5738cc1771b143" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string19 = /del\sGreen\.vbs/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string20 = /del\sPs1ToVbs\.ps1\\"/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string21 = "e74146d0354389935edf4ef0dcfdf659572b1444db54f08cf0c7ade206fee3c5" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string22 = "INotGreen/GlllPowerloader" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string23 = "powershell_to_vbs,APC_Injection,RemoteThreadContext,RemoteThreadSuspended" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string24 = /powershell_to_vbs\.ps1/ nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string25 = "Sleeping for 10 seconds to avoid in-memory AV scan" nocase ascii wide
        // Description: Sample to bypass AV/EDR and upload to transfer.sh
        // Reference: https://github.com/INotGreen/GlllPowerloader
        $string26 = /\-\-upload\-file.{0,100}transfer\.sh/ nocase ascii wide
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
