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
        $string1 = /.{0,1000}\s\-bindPipe\s.{0,1000}\s\-destHost\s.{0,1000}\s\-destPort\s.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string2 = /.{0,1000}\s\-remote\s\-bindPipe\s.{0,1000}\s\s\-bindPort\s.{0,1000}\s\-security.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string3 = /.{0,1000}\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-bindPort\s.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string4 = /.{0,1000}Invoke\-Piper.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string5 = /.{0,1000}Invoke\-PiperClient.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string6 = /.{0,1000}Invoke\-PiperServer.{0,1000}/ nocase ascii wide
        // Description: Forward local or remote tcp ports through SMB pipes.
        // Reference: https://github.com/p3nt4/Invoke-Piper
        $string7 = /.{0,1000}\-remote\s\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-destHost\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
