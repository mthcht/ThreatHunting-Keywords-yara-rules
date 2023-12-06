rule elevationstation
{
    meta:
        description = "Detection patterns for the tool 'elevationstation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elevationstation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string1 = /\.exe\s\-uac/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string2 = /\/elevateit\.bat/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string3 = /\\\\\\\\\.\\\\pipe\\\\warpzone8/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string4 = /\\\\\\\\127\.0\.0\.1\\\\pipe\\\\warpzone8/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string5 = /\\elevateit\.bat/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string6 = /cmd\.exe\s\/c\ssc\sstart\splumber/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string7 = /easinvoker\.exe.{0,1000}System32/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string8 = /elevationstation\.cpp/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string9 = /elevationstation\.exe/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string10 = /elevationstation\.git/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string11 = /elevationstation\.sln/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string12 = /elevationstation\-main/ nocase ascii wide
        // Description: github user hosting multiple exploitation tools
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string13 = /github\.com\/g3tsyst3m/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string14 = /n0de\.exe.{0,1000}elevationstation/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string15 = /sc\screate\splumber.{0,1000}warpzoneclient/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string16 = /sc\sdelete\splumber/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string17 = /tokenprivs\.cpp/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string18 = /tokenprivs\.exe/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string19 = /uac_easinvoker\./ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string20 = /uacbypass_files/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string21 = /users\\\\public\\\\elevationstation\.js/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string22 = /users\\\\usethis\\\\NewFile\.txt/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string23 = /warpzoneclient\.cpp/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string24 = /warpzoneclient\.exe/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string25 = /warpzoneclient\.exe/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string26 = /warpzoneclient\.sln/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string27 = /warpzoneclient\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
