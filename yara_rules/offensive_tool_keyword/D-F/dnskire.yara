rule dnskire
{
    meta:
        description = "Detection patterns for the tool 'dnskire' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnskire"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string1 = /\sdnskire\:dnskire\s/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string2 = /\smkzoneslices\.sh/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string3 = /\s\-R\sdnskire\:bind\s/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string4 = /\/certs\/dnsKIRE\.local\.crt/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string5 = /\/certs\/dnsKIRE\.local\.key/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string6 = /\/CN\=dnsKIRE\.local/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string7 = /\/db\/dnskire\.db/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string8 = /\/dnskire\.git/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string9 = /\/dnskire\.js/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string10 = /\/dnskire\.log/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string11 = /\/dnskire\/\.ssh\// nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string12 = /\/mkzoneslices\.sh/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string13 = /\\dnskire\.js/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string14 = /0fd74299abc6f3a23b609351d6fc3e7c524b2e4652a4691ec11c9c6ec1ab48d2/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string15 = /0xtosh\/dnskire/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string16 = /14cacb095c7f6d3347fe36b6576fde73047897330bae662fc29ef9f8169e0136/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string17 = /7acb019f05541c2f8549a9d7250b5bb2c6cad5a795b73e874fbc0865fdb4719b/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string18 = /d685191b55fec64ce5fa0ced8bff472aa1a297d0e77354da28f34d0f67a4dec4/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string19 = /DNS\sretrieval\sdone\s\-\sconverting\sto\sfile/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string20 = /dnskire\sALL\=\(ALL\:ALL\)\sNOPASSWD\:\sALL/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string21 = /dnskire\smay.{0,1000}\(ALL\s\:\sALL\)\sNOPASSWD\:\sALL.{0,1000}/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string22 = /dnsKIRE\sstarted\!\\n/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string23 = /dnskire\-install/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string24 = /Get\-Content\s\-path\s\$dnshexfile\s/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string25 = /https\:\/\/1\.3\.3\.7\:8081/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string26 = /IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgZG5zLnJlc29sdmVyCmltcG9ydCBvcwppbXBvcnQgcmFuZG9tCmltcG9ydCB0aW1lCgo\=/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string27 = /mkdir\sdnskire\// nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string28 = /node\sdnskire\.js/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string29 = /screen\s\-S\sdnskire\s\-/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string30 = /scripts\/zoneadm\.sh/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string31 = /sudo\s\-l\s\-U\sdnskire/ nocase ascii wide
        // Description: A tool for file infiltration over DNS
        // Reference: https://github.com/0xtosh/dnskire
        $string32 = /totally\-not\-meterpreter\.7z/ nocase ascii wide

    condition:
        any of them
}