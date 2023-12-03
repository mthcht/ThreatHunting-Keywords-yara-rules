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
        $string1 = /.{0,1000}brave.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp.{0,1000}/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string2 = /.{0,1000}brave\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\.{0,1000}/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string3 = /.{0,1000}chrome.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp.{0,1000}/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string4 = /.{0,1000}chrome\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\.{0,1000}/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string5 = /.{0,1000}msedge.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp.{0,1000}/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment -  abused by attackers
        // Reference: https://www.splunk.com/en_us/blog/security/mockbin-and-the-art-of-deception-tracing-adversaries-going-headless-and-mocking-apis.html
        $string6 = /.{0,1000}msedge.{0,1000}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=.{0,1000}/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string7 = /.{0,1000}msedge\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\.{0,1000}/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string8 = /.{0,1000}opera.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp.{0,1000}/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string9 = /.{0,1000}opera\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\.{0,1000}/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string10 = /.{0,1000}vivaldi.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp.{0,1000}/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string11 = /.{0,1000}vivaldi\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
