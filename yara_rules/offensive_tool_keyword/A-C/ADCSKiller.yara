rule ADCSKiller
{
    meta:
        description = "Detection patterns for the tool 'ADCSKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure
        // Reference: https://github.com/grimlockx/ADCSKiller
        $string1 = /\/ADCSKiller/ nocase ascii wide
        // Description: ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure
        // Reference: https://github.com/grimlockx/ADCSKiller
        $string2 = /adcskiller\.py/ nocase ascii wide
        // Description: ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure
        // Reference: https://github.com/grimlockx/ADCSKiller
        $string3 = /ly4k\/Certipy/ nocase ascii wide
        // Description: ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure
        // Reference: https://github.com/grimlockx/ADCSKiller
        $string4 = /p0dalirius\/Coercer/ nocase ascii wide

    condition:
        any of them
}
