rule WMEye
{
    meta:
        description = "Detection patterns for the tool 'WMEye' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMEye"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string1 = /\/WMEye\.git/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string2 = /\/wmeye\// nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string3 = /\[X\]\sShellCode\sProperty\sCreated/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string4 = /\[X\]\sUploading\sShellcode\sinto\starget/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string5 = /\\wmeye\.csproj/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string6 = /\\wmeye\.pdb/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string7 = /080de56a40e4ff15b0157da0224988a36f3e7c2347d58824ab3880f338d3eaec/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string8 = /928120DC\-5275\-4806\-B99B\-12D67B710DC0/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string9 = /namespace\sWmEye/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string10 = /OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH\/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string11 = /public\sclass\sWmEye/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string12 = /pwn1sher\/WMEye/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string13 = /wmeye\.csproj/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string14 = /wmeye\.exe\s/ nocase ascii wide
        // Description: WMEye is a post exploitation tool that uses WMI Event Filter and MSBuild Execution for Lateral Movement
        // Reference: https://github.com/pwn1sher/WMEye
        $string15 = /wmeye\.sln/ nocase ascii wide

    condition:
        any of them
}
