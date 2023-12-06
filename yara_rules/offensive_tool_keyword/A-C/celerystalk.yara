rule celerystalk
{
    meta:
        description = "Detection patterns for the tool 'celerystalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "celerystalk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: celerystalk helps you automate your network scanning/enumeration process with asynchronous jobs (aka tasks) while retaining full control of which tools you want to run.
        // Reference: https://github.com/sethsec/celerystalk
        $string1 = /celerystalk/ nocase ascii wide

    condition:
        any of them
}
