rule smb_reverse_shell
{
    meta:
        description = "Detection patterns for the tool 'smb-reverse-shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smb-reverse-shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string1 = /\/smb\-reverse\-shell/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string2 = /invoke.{0,1000}\s\-Action\scommand\s\-Execute\s.{0,1000}\s\-Session/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string3 = /Invoke\-SmbObey\s/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string4 = /Invoke\-SmbObey\./ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string5 = /Invoke\-SmbOrder\s/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string6 = /Invoke\-SmbOrder\./ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string7 = /smb\-reverse\-shell\.git/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string8 = /smb\-reverse\-shell\-main/ nocase ascii wide

    condition:
        any of them
}
