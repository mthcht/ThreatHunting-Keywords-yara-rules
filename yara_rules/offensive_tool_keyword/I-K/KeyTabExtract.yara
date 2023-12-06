rule KeyTabExtract
{
    meta:
        description = "Detection patterns for the tool 'KeyTabExtract' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyTabExtract"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files. which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm. Service Principal. Encryption Type and NTLM Hash
        // Reference: https://github.com/sosdave/KeyTabExtract
        $string1 = /KeyTabExtract/ nocase ascii wide

    condition:
        any of them
}
