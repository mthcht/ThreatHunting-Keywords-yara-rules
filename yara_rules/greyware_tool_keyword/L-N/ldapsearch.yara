rule ldapsearch
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string1 = /ldapsearch\s.{0,1000}\sldap\:\/\//
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string2 = /ldapsearch\s\-x\s\-h\s.{0,1000}\s\-s\sbase/
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string3 = /ldapsearch\s\-h\s.{0,1000}\s\-x/

    condition:
        any of them
}
