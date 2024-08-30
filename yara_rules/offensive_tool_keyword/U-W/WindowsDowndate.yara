rule WindowsDowndate
{
    meta:
        description = "Detection patterns for the tool 'WindowsDowndate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindowsDowndate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string1 = /\swindows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string2 = /\/windows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string3 = /\/WindowsDowndate\.git/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string4 = /\\windows_downdate\.py/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string5 = /\\WindowsDowndate\-main/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string6 = /0a0be178cd014f569eac8697ce355c7ceb59b7e1a3aaa18673a7ffde4a044c88/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string7 = /50eb54d0976374701c6051c23b993708\,4d67d3d82b1adcc1b96e743e9b0efaaa8a566e3d\,a34e71ededf334d3d6a480e3738c91fccbb4d2c1fbeec7192db9793a2541e8ca/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string8 = /CVE\-2021\-27090\-Secure\-Kernel\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string9 = /CVE\-2022\-34709\-Credential\-Guard\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string10 = /CVE\-2023\-21768\-AFD\-Driver\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string11 = /dab858feab4506727059fda4645865e2029892c6560704a7077433bab5d5ca0e/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string12 = /from\swindows_downdate\./ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string13 = /Hyper\-V\-Hypervisor\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string14 = /Kernel\-Suite\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string15 = /PPLFault\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string16 = /SafeBreach\-Labs\/WindowsDowndate/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string17 = /Starting\sWindows\-Downdate/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string18 = /VBS\-UEFI\-Locks\-Bypass\/Config\.xml/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string19 = /Windows\sDowndate\:\sCraft\sany\sdowngrading\sWindows\sUpdates/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string20 = /windows_downdate\.exe/ nocase ascii wide
        // Description: A tool that takes over Windows Updates to craft custom downgrades and expose past fixed vulnerabilities
        // Reference: https://github.com/SafeBreach-Labs/WindowsDowndate
        $string21 = /Windows\-Downdate\smust\sbe\srun\sas\san\sAdministrator/ nocase ascii wide

    condition:
        any of them
}
