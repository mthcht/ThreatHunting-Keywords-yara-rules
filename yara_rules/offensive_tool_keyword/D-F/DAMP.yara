rule DAMP
{
    meta:
        description = "Detection patterns for the tool 'DAMP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DAMP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string1 = /.{0,1000}\/DAMP\.git.{0,1000}/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string2 = /.{0,1000}Add\-RemoteRegBackdoor.{0,1000}/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string3 = /.{0,1000}DAMP\-master\.zip/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string4 = /.{0,1000}Get\-RemoteCachedCredential.{0,1000}/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string5 = /.{0,1000}Get\-RemoteLocalAccountHash.{0,1000}/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string6 = /.{0,1000}HarmJ0y\/DAMP.{0,1000}/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string7 = /.{0,1000}RemoteHashRetrieval\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
