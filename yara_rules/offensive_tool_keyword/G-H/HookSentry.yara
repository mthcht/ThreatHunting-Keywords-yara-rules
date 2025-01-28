rule HookSentry
{
    meta:
        description = "Detection patterns for the tool 'HookSentry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HookSentry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string1 = /\/HookSentry\.exe/ nocase ascii wide
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string2 = /\/HookSentry\.git/ nocase ascii wide
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string3 = "050243af07ab26ee16ed59f35a1d7944db273a40aba1c3e70438c3a8e0d2a923" nocase ascii wide
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string4 = "b6aa7aa16083b7113fe5fe662a497c6c03a3c4aa74ff2c379b64fd9e9b495bcf" nocase ascii wide
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string5 = "ce613fc8-3f97-4989-bc90-2027463ea37d" nocase ascii wide
        // Description: tool for inspecting system DLLs loaded into processes - looking for functions hooked from AV/EDR.
        // Reference: https://github.com/UmaRex01/HookSentry
        $string6 = "UmaRex01/HookSentry" nocase ascii wide

    condition:
        any of them
}
