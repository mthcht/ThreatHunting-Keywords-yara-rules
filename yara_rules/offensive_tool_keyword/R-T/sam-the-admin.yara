rule sam_the_admin
{
    meta:
        description = "Detection patterns for the tool 'sam-the-admin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sam-the-admin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: script used in the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/WazeHell/sam-the-admin/tree/main/utils
        $string1 = /.{0,1000}\/utils\/addcomputer\.py.{0,1000}/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/WazeHell/sam-the-admin/tree/main/utils
        $string2 = /.{0,1000}sam_the_admin\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
