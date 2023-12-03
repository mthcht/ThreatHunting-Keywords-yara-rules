rule Offensive_Payloads
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string1 = /.{0,1000}Cross\-Site\-Scripting\-XSS\-Payloads.{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string2 = /.{0,1000}Directory\-Traversal\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string3 = /.{0,1000}File\-Extensions\-Wordlist\.txt.{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string4 = /.{0,1000}Html\-Injection\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string5 = /.{0,1000}Html\-Injection\-Read\-File\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string6 = /.{0,1000}OS\-Command\-Injection\-Unix\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string7 = /.{0,1000}OS\-Command\-Injection\-Windows\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string8 = /.{0,1000}PHP\-Code\-injection\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string9 = /.{0,1000}PHP\-Code\-Injections\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string10 = /.{0,1000}Server\-Side\-Request\-Forgery\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string11 = /.{0,1000}SQL\-Injection\-Auth\-Bypass\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string12 = /.{0,1000}SQL\-Injection\-Payloads\..{0,1000}/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string13 = /.{0,1000}XML\-External\-Entity\-\(XXE\)\-Payloads.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
