rule chromium
{
    meta:
        description = "Detection patterns for the tool 'chromium' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromium"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string1 = /brave.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string2 = /brave\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string3 = /chrome.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string4 = /chrome\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string5 = /msedge.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment -  abused by attackers
        // Reference: https://www.splunk.com/en_us/blog/security/mockbin-and-the-art-of-deception-tracing-adversaries-going-headless-and-mocking-apis.html
        $string6 = /msedge.{0,1000}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string7 = /msedge\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string8 = /opera.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string9 = /opera\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string10 = /vivaldi.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string11 = /vivaldi\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide

    condition:
        any of them
}
