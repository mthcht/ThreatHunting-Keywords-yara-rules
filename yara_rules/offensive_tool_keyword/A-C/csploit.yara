rule csploit
{
    meta:
        description = "Detection patterns for the tool 'csploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The most complete and advanced IT security professional toolkit on Android.
        // Reference: https://github.com/cSploit/android
        $string1 = /.{0,1000}cSploit\-.{0,1000}\.apk.{0,1000}/ nocase ascii wide
        // Description: The most complete and advanced IT security professional toolkit on Android.
        // Reference: https://github.com/cSploit/android
        $string2 = /.{0,1000}cSploit\/android.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
