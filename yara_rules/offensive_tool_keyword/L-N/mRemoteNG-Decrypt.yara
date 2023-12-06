rule mRemoteNG_Decrypt
{
    meta:
        description = "Detection patterns for the tool 'mRemoteNG-Decrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mRemoteNG-Decrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/haseebT/mRemoteNG-Decrypt
        $string1 = /\/mRemoteNG\-Decrypt/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/haseebT/mRemoteNG-Decrypt
        $string2 = /mremoteng_decrypt\.py/ nocase ascii wide

    condition:
        any of them
}
