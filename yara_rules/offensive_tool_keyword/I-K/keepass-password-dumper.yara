rule keepass_password_dumper
{
    meta:
        description = "Detection patterns for the tool 'keepass-password-dumper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keepass-password-dumper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KeePass Master Password Dumper is a simple proof-of-concept tool used to dump the master password from KeePass's memory. Apart from the first password character it is mostly able to recover the password in plaintext. No code execution on the target system is required. just a memory dump
        // Reference: https://github.com/vdohney/keepass-password-dumper
        $string1 = /keepass\-password\-dumper/ nocase ascii wide

    condition:
        any of them
}
