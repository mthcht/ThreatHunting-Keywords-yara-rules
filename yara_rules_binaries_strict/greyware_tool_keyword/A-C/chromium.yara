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
        $string1 = /brave.{0,100}\s\-\-headless\s.{0,100}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string2 = /brave\.exe.{0,100}\s\-\-load\-extension\=\\".{0,100}\\Users\\.{0,100}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string3 = /chrome.{0,100}\s\-\-headless\s.{0,100}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string4 = /chrome\.exe.{0,100}\s\-\-load\-extension\=\\".{0,100}\\Users\\.{0,100}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string5 = /msedge.{0,100}\s\-\-headless\s.{0,100}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment -  abused by attackers
        // Reference: https://www.splunk.com/en_us/blog/security/mockbin-and-the-art-of-deception-tracing-adversaries-going-headless-and-mocking-apis.html
        $string6 = /msedge.{0,100}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string7 = /msedge\.exe.{0,100}\s\-\-load\-extension\=\\".{0,100}\\Users\\.{0,100}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string8 = /opera.{0,100}\s\-\-headless\s.{0,100}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string9 = /opera\.exe.{0,100}\s\-\-load\-extension\=\\".{0,100}\\Users\\.{0,100}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string10 = /vivaldi.{0,100}\s\-\-headless\s.{0,100}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string11 = /vivaldi\.exe.{0,100}\s\-\-load\-extension\=\\".{0,100}\\Users\\.{0,100}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
