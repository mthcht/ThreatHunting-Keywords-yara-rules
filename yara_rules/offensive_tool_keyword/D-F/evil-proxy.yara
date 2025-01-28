rule evil_proxy
{
    meta:
        description = "Detection patterns for the tool 'evil-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string1 = " evil-proxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string2 = /\sevil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string3 = " install evil-proxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string4 = /\.\/evil\-proxy/
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string5 = /\/evil\-proxy\.git/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string6 = /\/evil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string7 = "/evil-proxy/"
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string8 = "@mitm_pattern = " nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string9 = "@mitm_port = " nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string10 = "@mitm_servers =" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string11 = /\\evil\-proxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string12 = /\\evil\-proxy\\/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string13 = "= \"evil-proxy\"" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string14 = /127\.0\.0\.1\:\#\{mitm_port\}/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string15 = /A\sruby\shttp\/https\sproxy\sto\sdo\sEVIL\sthings\./ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string16 = "bbtfr/evil-proxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string17 = /evil\-proxy\.gemspec/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string18 = "evil-proxy/agentproxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string19 = "evil-proxy/httpproxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string20 = "evil-proxy/selenium" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string21 = "evil-proxy/version" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string22 = "EvilProxy::HTTPProxyServer" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string23 = "EvilProxy::MITMProxyServer" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string24 = /evil\-proxy\-0\.1\.0/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string25 = /evil\-proxy\-0\.2\.0/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string26 = "evil-proxy-master" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string27 = "gem 'evil-proxy'" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string28 = /http\:\/\/101\.251\.217\.210/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string29 = /HTTPClient\.post\(\'https\:\/\/httpbin\.org\/post/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string30 = /mitmproxy\.rb/ nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string31 = "module EvilProxy" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string32 = "require 'evil-proxy'" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string33 = "require 'evil-proxy/async'" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string34 = "require 'evil-proxy/store'" nocase ascii wide
        // Description: A ruby http/https proxy to do EVIL things
        // Reference: https://github.com/bbtfr/evil-proxy
        $string35 = "vil-proxy/quickcert" nocase ascii wide

    condition:
        any of them
}
