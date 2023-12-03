rule WebDavC2
{
    meta:
        description = "Detection patterns for the tool 'WebDavC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebDavC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string1 = /.{0,1000}\/WebDavC2\.git.{0,1000}/ nocase ascii wide
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string2 = /.{0,1000}Arno0x\/WebDavC2.{0,1000}/ nocase ascii wide
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string3 = /.{0,1000}WebDavC2.{0,1000}/ nocase ascii wide
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string4 = /.{0,1000}webdavC2\.py.{0,1000}/ nocase ascii wide
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string5 = /.{0,1000}WebDavC2\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: WebDavC2 is a PoC of using the WebDAV protocol with PROPFIND only requests to serve as a C2 communication channel between an agent. running on the target system. and a controller acting as the actuel C2 server.
        // Reference: https://github.com/Arno0x/WebDavC2
        $string6 = /.{0,1000}webdavC2server\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
