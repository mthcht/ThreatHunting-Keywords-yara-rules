rule windapsearch
{
    meta:
        description = "Detection patterns for the tool 'windapsearch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windapsearch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string1 = /\s\-d\s.{0,1000}\s\-u\s.{0,1000}\\.{0,1000}\s\-p\s.{0,1000}\s\-\-da/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string2 = /\s\-\-unconstrained\-users/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string3 = /\s\-\-user\-spns/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string4 = /\/windapsearch\.git/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string5 = /windapsearch\.py/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string6 = /windapsearch_py2\.py/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string7 = /windapsearch\-master/ nocase ascii wide

    condition:
        any of them
}
