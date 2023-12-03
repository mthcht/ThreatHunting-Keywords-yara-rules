rule scshell
{
    meta:
        description = "Detection patterns for the tool 'scshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCShell is a fileless lateral movement tool that relies on ChangeServiceConfigA to run commands. The beauty of this tool is that it does not perform authentication against SMB. Everything is performed over DCERPC.The utility can be used remotely WITHOUT registering a service or creating a service. It also doesn't have to drop any file on the remote system* (Depend on the technique used to execute)
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string1 = /.{0,1000}\/scshell.{0,1000}/ nocase ascii wide
        // Description: network pentestration test (shell)
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string2 = /.{0,1000}payload\.csproj.{0,1000}/ nocase ascii wide
        // Description: network pentestration test (shell)
        // Reference: https://github.com/Mr-Un1k0d3r/SCShell
        $string3 = /.{0,1000}payload\.sct\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
