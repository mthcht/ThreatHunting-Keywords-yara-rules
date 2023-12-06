rule mimipenguin
{
    meta:
        description = "Detection patterns for the tool 'mimipenguin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimipenguin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to dump the login password from the current linux desktop user. Adapted from the idea behind the popular Windows tool mimikatz. This was assigned CVE-2018-20781 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20781). Fun fact its still not fixed after GNOME Keyring 3.27.2 and still works as of 3.28.0.2-1ubuntu1.18.04.1.
        // Reference: https://github.com/huntergregal/mimipenguin
        $string1 = /mimipenguin/ nocase ascii wide

    condition:
        any of them
}
