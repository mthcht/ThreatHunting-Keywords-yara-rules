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
        $string1 = /.{0,1000}\.exe\s\-uac/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string2 = /.{0,1000}\/elevateit\.bat.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string3 = /.{0,1000}\\\\\\\\\.\\\\pipe\\\\warpzone8.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string4 = /.{0,1000}\\\\\\\\127\.0\.0\.1\\\\pipe\\\\warpzone8.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string5 = /.{0,1000}\\elevateit\.bat.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string6 = /.{0,1000}cmd\.exe\s\/c\ssc\sstart\splumber.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string7 = /.{0,1000}easinvoker\.exe.{0,1000}System32.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string8 = /.{0,1000}elevationstation\.cpp.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string9 = /.{0,1000}elevationstation\.exe.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string10 = /.{0,1000}elevationstation\.git.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string11 = /.{0,1000}elevationstation\.sln.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string12 = /.{0,1000}elevationstation\-main.{0,1000}/ nocase ascii wide
        // Description: github user hosting multiple exploitation tools
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string13 = /.{0,1000}github\.com\/g3tsyst3m.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string14 = /.{0,1000}n0de\.exe.{0,1000}elevationstation.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string15 = /.{0,1000}sc\screate\splumber.{0,1000}warpzoneclient.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string16 = /.{0,1000}sc\sdelete\splumber.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string17 = /.{0,1000}tokenprivs\.cpp.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string18 = /.{0,1000}tokenprivs\.exe.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string19 = /.{0,1000}uac_easinvoker\..{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string20 = /.{0,1000}uacbypass_files.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string21 = /.{0,1000}users\\\\public\\\\elevationstation\.js.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string22 = /.{0,1000}users\\\\usethis\\\\NewFile\.txt.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string23 = /.{0,1000}warpzoneclient\.cpp.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string24 = /.{0,1000}warpzoneclient\.exe.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string25 = /.{0,1000}warpzoneclient\.exe.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string26 = /.{0,1000}warpzoneclient\.sln.{0,1000}/ nocase ascii wide
        // Description: elevate to SYSTEM any way we can! Metasploit and PSEXEC getsystem alternative
        // Reference: https://github.com/g3tsyst3m/elevationstation
        $string27 = /.{0,1000}warpzoneclient\.vcxproj.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
