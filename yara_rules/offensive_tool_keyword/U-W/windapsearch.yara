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
        $string1 = /.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\\.{0,1000}\s\-p\s.{0,1000}\s\-\-da.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string2 = /.{0,1000}\s\-\-unconstrained\-users.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string3 = /.{0,1000}\s\-\-user\-spns.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string4 = /.{0,1000}\/windapsearch\.git.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string5 = /.{0,1000}windapsearch\.py.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string6 = /.{0,1000}windapsearch_py2\.py.{0,1000}/ nocase ascii wide
        // Description: Python script to enumerate users - groups and computers from a Windows domain through LDAP queries
        // Reference: https://github.com/ropnop/windapsearch
        $string7 = /.{0,1000}windapsearch\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
