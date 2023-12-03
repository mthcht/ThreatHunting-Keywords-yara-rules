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
        $string1 = /.{0,1000}\/mRemoteNG\-Decrypt.{0,1000}/ nocase ascii wide
        // Description: Python script to decrypt passwords stored by mRemoteNG
        // Reference: https://github.com/haseebT/mRemoteNG-Decrypt
        $string2 = /.{0,1000}mremoteng_decrypt\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
