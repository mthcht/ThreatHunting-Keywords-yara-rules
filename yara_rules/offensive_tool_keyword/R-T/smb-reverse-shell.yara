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
        $string1 = /.{0,1000}\/smb\-reverse\-shell.{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string2 = /.{0,1000}invoke.{0,1000}\s\-Action\scommand\s\-Execute\s.{0,1000}\s\-Session.{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string3 = /.{0,1000}Invoke\-SmbObey\s.{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string4 = /.{0,1000}Invoke\-SmbObey\..{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string5 = /.{0,1000}Invoke\-SmbOrder\s.{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string6 = /.{0,1000}Invoke\-SmbOrder\..{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string7 = /.{0,1000}smb\-reverse\-shell\.git.{0,1000}/ nocase ascii wide
        // Description: A Reverse Shell which uses an XML file on an SMB share as a communication channel.
        // Reference: https://github.com/r1cksec/smb-reverse-shell
        $string8 = /.{0,1000}smb\-reverse\-shell\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
