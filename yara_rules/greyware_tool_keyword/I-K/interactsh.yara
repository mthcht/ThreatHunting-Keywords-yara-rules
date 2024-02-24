rule interactsh
{
    meta:
        description = "Detection patterns for the tool 'interactsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "interactsh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C4
        // Reference: https://github.com/projectdiscovery/interactsh
        $string1 = /\.exec.{0,1000}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C7
        // Reference: https://github.com/projectdiscovery/interactsh
        $string2 = /\.interactsh\.com/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C5
        // Reference: https://github.com/projectdiscovery/interactsh
        $string3 = /\/interactsh\// nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C6
        // Reference: https://github.com/projectdiscovery/interactsh
        $string4 = /\/interactsh\-client/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C15
        // Reference: https://github.com/projectdiscovery/interactsh
        $string5 = /\/interactsh\-collaborator/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C8
        // Reference: https://github.com/projectdiscovery/interactsh
        $string6 = /\/interactsh\-server/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C3
        // Reference: https://github.com/projectdiscovery/interactsh
        $string7 = /curl.{0,1000}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C4
        // Reference: https://github.com/projectdiscovery/interactsh
        $string8 = /http\:\/\/.{0,1000}\.interact\.sh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C10
        // Reference: https://github.com/projectdiscovery/interactsh
        $string9 = /interactsh\s\-/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C9
        // Reference: https://github.com/projectdiscovery/interactsh
        $string10 = /interactsh.{0,1000}\.exe/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C14
        // Reference: https://github.com/projectdiscovery/interactsh
        $string11 = /interactsh.{0,1000}oast\./ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C11
        // Reference: https://github.com/projectdiscovery/interactsh
        $string12 = /interactsh\-client\s\-/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C13
        // Reference: https://github.com/projectdiscovery/interactsh
        $string13 = /interactsh\-server\s\-/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C12
        // Reference: https://github.com/projectdiscovery/interactsh
        $string14 = /projectdiscovery\/interactsh/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C2
        // Reference: https://github.com/projectdiscovery/interactsh
        $string15 = /wget.{0,1000}\.interact\.sh/ nocase ascii wide

    condition:
        any of them
}
