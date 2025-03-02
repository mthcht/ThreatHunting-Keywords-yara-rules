rule attrib
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command aiming to hide a file.  It can be performed with attrib.exe on a WINDOWS machine with command option +h 
        // Reference: N/A
        $string1 = /\\attrib\.exe.{0,100}\s\+H\s/ nocase ascii wide
        // Description: hide evidence of RDP connections
        // Reference: https://github.com/xiaoy-sec/Pentest_Note/blob/52156f816f0c2497c25343c2e872130193acca80/wiki/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87/Windows%E6%8F%90%E6%9D%83/RDP%26Firewall/%E5%88%A0%E9%99%A4%E7%97%95%E8%BF%B9.md?plain=1#L4
        $string2 = /attrib\s.{0,100}\.rdp\s\-s\s\-h/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string3 = /attrib\s\+R\s\+S\s\+H\sC\:\\WINDOWS\\scvhost\.exe/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string4 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\Program\sFiles\\Windows\sNT\\/ nocase ascii wide
        // Description: defense evasion - hidding in suspicious directory
        // Reference: N/A
        $string5 = /attrib\s\+s\s\+h\s\/D\s\\"C\:\\users\\Public\\/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string6 = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
        // Description: instruments explorer to treat the folder as ActiveX cache
        // Reference: https://x.com/ValthekOn/status/1890160938407596168
        $string7 = /attrib\sdesktop\.ini\s\+s\s\+h\s\+r/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string8 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\explorer\.exe/ nocase ascii wide
        // Description: suspicious attrib command
        // Reference: https://github.com/petikvx/vx-ezine/blob/cfaf09bb089a08a9f33254929209fb32ebd52806/darkcodes/dc1/Sources/Sph1nX_Sources/DeskLock/DeskLock.txt#L13
        $string9 = /attrib\s\-R\s\-S\s\-H\sC\:\\WINDOWS\\System32\\explorer\.exe/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = "attrib -s -h %userprofile%" nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string11 = /attrib\s\-s\s\-h\s\%userprofile\%\\documents\\Default\.rdp/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string12 = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
        // Description: instruments explorer to treat the folder as ActiveX cache
        // Reference: https://x.com/ValthekOn/status/1890160938407596168
        $string13 = /echo\sCLSID\=\{88C6C381\-2E85\-11D0\-94DE\-444553540000\}\s\>\>\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string14 = /echo\sIconResource\=\\\\.{0,100}\\.{0,100}\s\>\>\sdesktop\.ini/ nocase ascii wide
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
