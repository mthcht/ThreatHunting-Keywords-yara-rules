rule bypassUAC
{
    meta:
        description = "Detection patterns for the tool 'bypassUAC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypassUAC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC bypass for Windows
        // Reference: https://github.com/ASkyeye/win-server2022-UAC-Bypass
        $string1 = /\s\-OutputAssembly\s\\"sl0p\.dll\\"/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string2 = /\sUAC\-Bypass\.ps1/ nocase ascii wide
        // Description: UAC bypass for Windows
        // Reference: https://github.com/ASkyeye/win-server2022-UAC-Bypass
        $string3 = /\/sl0p\.dll/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string4 = /\/UAC\-Bypass\.ps1/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string5 = /\\iscsicpl_bypassUAC/ nocase ascii wide
        // Description: UAC bypass for Windows
        // Reference: https://github.com/ASkyeye/win-server2022-UAC-Bypass
        $string6 = /\\sl0p\.dll/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string7 = /\\UAC\-Bypass\.ps1/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string8 = "0acffe2314b3329c3a984cd5b402bf17e1de0305b38d9e1daa5f566182dbef6f" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string9 = "4494BDD20D3FA171BF25A733B6755A6BE88F97BAEBB98820A385CE2D4BE9BE0F" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string10 = "4d3bae5b-eb71-413b-adb2-a58f1fa2ad64" nocase ascii wide
        // Description: UAC bypass for Windows
        // Reference: https://github.com/ASkyeye/win-server2022-UAC-Bypass
        $string11 = "4e3beb361e85dab6b6f15e0c72e8e47376d0b678dd7ba537c24a5e0e5085ea7c" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string12 = "804E7688C41C080042845DEA6461DAE99DAB16204788E4BEE1C7476AD1280674" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string13 = "8845A8AF-34DC-4EBC-8223-B35F8CC8A900" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string14 = "Aka    : x0xr00t" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string15 = "iscsicpl autoelevate DLL Search Order hijacking UAC Bypass" nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string16 = /iscsicpl_BypassUAC_x86\.exe/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string17 = /ISecurityEditorUAC_off\.exe/ nocase ascii wide
        // Description: UAC bypass for x64 Windows 7 - 11
        // Reference: https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
        $string18 = "Name   : UAC Bypass Win Server 2022" nocase ascii wide

    condition:
        any of them
}
