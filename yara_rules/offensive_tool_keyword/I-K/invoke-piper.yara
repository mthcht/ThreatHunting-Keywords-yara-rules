rule invoke_piper
{
    meta:
        description = "Detection patterns for the tool 'invoke-piper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "invoke-piper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string1 = /\s\-bindPipe\s.{0,1000}\s\-destHost\s.{0,1000}\s\-destPort\s/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string2 = /\s\-remote\s\-bindPipe\s.{0,1000}\s\s\-bindPort\s.{0,1000}\s\-security/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string3 = /\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-bindPort\s/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string4 = /Invoke\-Piper/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string5 = /Invoke\-PiperClient/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string6 = /Invoke\-PiperServer/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string7 = /\-remote\s\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-destHost\s/ nocase ascii wide

    condition:
        any of them
}
