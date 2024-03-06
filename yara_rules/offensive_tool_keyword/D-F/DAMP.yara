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
        $string1 = /\/DAMP\.git/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string2 = /Add\-RemoteRegBackdoor/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string3 = /DAMP\-master\.zip/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string4 = /Get\-RemoteCachedCredential/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string5 = /Get\-RemoteCachedCredential/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string6 = /Get\-RemoteLocalAccountHash/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string7 = /Get\-RemoteLocalAccountHash/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string8 = /Get\-RemoteMachineAccountHash/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string9 = /HarmJ0y\/DAMP/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string10 = /powerdump\.ps1/ nocase ascii wide
        // Description: The Discretionary ACL Modification Project: Persistence Through Host-based Security Descriptor Modification.
        // Reference: https://github.com/HarmJ0y/DAMP
        $string11 = /RemoteHashRetrieval\.ps1/ nocase ascii wide

    condition:
        any of them
}
