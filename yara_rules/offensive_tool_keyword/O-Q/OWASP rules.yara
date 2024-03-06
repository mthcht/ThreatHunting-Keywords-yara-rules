rule OWASP_rules
{
    meta:
        description = "Detection patterns for the tool 'OWASP rules' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OWASP rules"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string1 = /\"small\sweb\sshell\sby\szaco/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string2 = /\/tmp\/evil\.sh/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string3 = /\-\:\[GreenwooD\]\:\-\sWinX\sShell/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string4 = /\<h1\>\.\:NCC\:\.\sShell\sv/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string5 = /\<H1\>\<center\>\-\=\[\+\]\sIDBTEAM\sSHELLS/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string6 = /\<h2\>Laudanum\sTools/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string7 = /\<head\>\<title\>Wardom\s\|\sNe\sMutlu\sT/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string8 = /\<title\>Sosyete\sSafe\sMode\sBypass\sShell\s\-/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string9 = /\<title\>SyRiAn\sSh3ll\s\~/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string10 = /\<title\>WebRoot\sHack\sTools\"/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string11 = /\=\[\s1n73ct10n\sprivat\sshell\s\]\=/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string12 = /\-\-\=\=\[\[\sAndela\sYuwono\sPriv8\sShell\s\]\]\=\=\-\-/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string13 = /0byt3m1n1\-V2/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string14 = /BloodSecurity\sHackers\sShell/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string15 = /chmod\s\+x\sevil\.php/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string16 = /Con7ext\sShell\sV\.2/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string17 = /CUPLIS\sBYPASSS\sSHELL/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string18 = /Dive\sShell\s\-\sEmperor\sHacking\sTeam/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string19 = /G\-Security\sWebshell/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string20 = /h4ntu\sshell\s\[powered\sby\stsoi\]/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string21 = /Laudanum\sPHP\sFile\sBrowser/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string22 = /Laudanum\sPHP\sHostname\sby\sIP\sLookup/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string23 = /Laudanum\sPHP\sProxy/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string24 = /Laudanum\sPHP\sShell\sAccess/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string25 = /Loader\'z\sWEB\sshell/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string26 = /Lolipop\.php\s\-\sEdited\sBy\sKingDefacer/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string27 = /Simple\sPHP\sbackdoor\sby\sDK/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string28 = /SimShell\s\-\sSimorgh\sSecurity\sMGZ/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string29 = /Small\sShell\s\-\sEdited\sBy\sKingDefacer/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string30 = /Yourman\.sh\sMini\sShell/ nocase ascii wide
        // Description: OWASP repo of rules - extracted strings for detection
        // Reference: https://github.com/coreruleset/coreruleset/
        $string31 = /ZEROSHELL\s\|\sZEROSTORE/ nocase ascii wide

    condition:
        any of them
}
