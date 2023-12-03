rule interactsh
{
    meta:
        description = "Detection patterns for the tool 'interactsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "interactsh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C4
        // Reference: https://github.com/projectdiscovery/interactsh
        $string1 = /.{0,1000}\.exec.{0,1000}\.interact\.sh.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C7
        // Reference: https://github.com/projectdiscovery/interactsh
        $string2 = /.{0,1000}\.interactsh\.com/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C5
        // Reference: https://github.com/projectdiscovery/interactsh
        $string3 = /.{0,1000}\/interactsh\/.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C6
        // Reference: https://github.com/projectdiscovery/interactsh
        $string4 = /.{0,1000}\/interactsh\-client.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C15
        // Reference: https://github.com/projectdiscovery/interactsh
        $string5 = /.{0,1000}\/interactsh\-collaborator.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C8
        // Reference: https://github.com/projectdiscovery/interactsh
        $string6 = /.{0,1000}\/interactsh\-server.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C3
        // Reference: https://github.com/projectdiscovery/interactsh
        $string7 = /.{0,1000}curl.{0,1000}\.interact\.sh.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C10
        // Reference: https://github.com/projectdiscovery/interactsh
        $string8 = /.{0,1000}interactsh\s\-.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C9
        // Reference: https://github.com/projectdiscovery/interactsh
        $string9 = /.{0,1000}interactsh.{0,1000}\.exe/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C14
        // Reference: https://github.com/projectdiscovery/interactsh
        $string10 = /.{0,1000}interactsh.{0,1000}oast\..{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C11
        // Reference: https://github.com/projectdiscovery/interactsh
        $string11 = /.{0,1000}interactsh\-client\s\-.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C13
        // Reference: https://github.com/projectdiscovery/interactsh
        $string12 = /.{0,1000}interactsh\-server\s\-.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C12
        // Reference: https://github.com/projectdiscovery/interactsh
        $string13 = /.{0,1000}projectdiscovery\/interactsh.{0,1000}/ nocase ascii wide
        // Description: Interactsh is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions but abused by attackers as C2
        // Reference: https://github.com/projectdiscovery/interactsh
        $string14 = /.{0,1000}wget.{0,1000}\.interact\.sh.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
