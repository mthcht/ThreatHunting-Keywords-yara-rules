rule FormThief
{
    meta:
        description = "Detection patterns for the tool 'FormThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FormThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string1 = /\/FormThief\.git/ nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string2 = /\\FormThief\-main/ nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string3 = "10CC4D5B-DC87-4AEB-887B-E47367BF656B" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string4 = "4B2E3A60-9A8F-4F36-8692-14ED9887E7BE" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string5 = "4ED3C17D-33E6-4B86-9FA0-DA774B7CD387" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string6 = "78DE9716-84E8-4469-A5AE-F3E43181C28B" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string7 = "D6948EFC-AA15-413D-8EF1-032C149D3FBB" nocase ascii wide
        // Description: Spoofing desktop login applications with WinForms and WPF
        // Reference: https://github.com/mlcsec/FormThief
        $string8 = "mlcsec/FormThief" nocase ascii wide

    condition:
        any of them
}
