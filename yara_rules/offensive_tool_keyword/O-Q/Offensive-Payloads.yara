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
        $string1 = /Cross\-Site\-Scripting\-XSS\-Payloads/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string2 = /Directory\-Traversal\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string3 = /File\-Extensions\-Wordlist\.txt/ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string4 = /Html\-Injection\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string5 = /Html\-Injection\-Read\-File\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string6 = /OS\-Command\-Injection\-Unix\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string7 = /OS\-Command\-Injection\-Windows\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string8 = /PHP\-Code\-injection\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string9 = /PHP\-Code\-Injections\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string10 = /Server\-Side\-Request\-Forgery\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string11 = /SQL\-Injection\-Auth\-Bypass\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string12 = /SQL\-Injection\-Payloads\./ nocase ascii wide
        // Description: List of payloads and wordlists that are specifically crafted to identify and exploit vulnerabilities in target web applications.
        // Reference: https://github.com/InfoSecWarrior/Offensive-Payloads/
        $string13 = /XML\-External\-Entity\-\(XXE\)\-Payloads/ nocase ascii wide

    condition:
        any of them
}
