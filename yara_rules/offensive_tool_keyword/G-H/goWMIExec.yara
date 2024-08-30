rule goWMIExec
{
    meta:
        description = "Detection patterns for the tool 'goWMIExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goWMIExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string1 = /\sgoWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string2 = /\sgoWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string3 = /\sgoWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string4 = /\/goWMIExec\.git/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string5 = /\/goWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string6 = /\/goWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string7 = /\/goWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string8 = /\\goWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string9 = /\\goWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string10 = /\\goWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string11 = /0e5ae252e2597d44f6e8def9fcdd3562954130a0261776e083959d067795c450/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string12 = /5c5dc6546877d616c4479df133654a0fbccc71d5279aa63f2ca560a5abfea31d/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string13 = /5cdce3c908a8a7a336d21543c1133071b6395e26ca882cafc05fb6dbdce075f1/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string14 = /C\-Sto\/goWMIExec/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string15 = /ef881142422dd10c7ad27424ce2407312b3886c5ee940a4be17153caed6ccaff/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string16 = /goWMIExec\s\-target\s/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string17 = /goWMIExec\/pkg/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string18 = /wmiexec\\wmiexec\.go/ nocase ascii wide

    condition:
        any of them
}
