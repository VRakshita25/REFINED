rule Gafgyt_BASHLITE_ELF {
    meta:
        description  = "Detects Gafgyt/BASHLITE DDoS botnet ELF"
        family       = "Gafgyt"
        type         = "DDoS Botnet"
        threat_actor = "Multiple operators (leaked source code)"
        mitre_attack = "T1498, T1059.004, T1071, T1105"
        severity     = "HIGH"
        reference    = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.gafgyt"

    strings:
        $s1 = "BASHLITE" ascii
        $s2 = "gafgyt" nocase ascii
        $s3 = "QBOT" ascii
        $s4 = "RIFT" ascii
        $c1 = "PING" ascii
        $c2 = "PONG" ascii
        $c3 = "GETLOCALIP" ascii
        $c4 = "SCANNER ON" ascii
        $c5 = "KILLATTK" ascii
        $c6 = "LOLNOGTFO" ascii
        $a1 = "HOLD" ascii
        $a2 = "JUNK" ascii
        $t1 = "root\x00vizxv" ascii
        $t2 = "root\x00xc3511" ascii
        $t3 = "root\x00hi3518" ascii
        $t4 = "admin\x00admin" ascii
        $t5 = "root\x00anko" ascii
        $t6 = "root\x00root" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 3MB
        and (
            1 of ($s*)
            or 3 of ($c*)
            or 3 of ($t*)
            or (2 of ($c*) and 1 of ($t*))
            or ($c1 and $c2 and 1 of ($a*))
        )
}

rule Gafgyt_Torlus {
    meta:
        description = "Detects Torlus variant of Gafgyt"
        family      = "Gafgyt/Torlus"
        type        = "DDoS Botnet"
        severity    = "HIGH"

    strings:
        $s1 = "TORLUS" ascii
        $s2 = "torlus" nocase ascii
        $s3 = "KILLATTK" ascii
        $s4 = "LOLNOGTFO" ascii

    condition:
        uint32(0) == 0x464C457F
        and 2 of them
}

rule Gafgyt_Credentials {
    meta:
        description = "Detects Gafgyt credential brute-force list"
        family      = "Gafgyt"
        type        = "DDoS Botnet"
        severity    = "MEDIUM"

    strings:
        $c1 = "root\x00vizxv" ascii
        $c2 = "root\x00xc3511" ascii
        $c3 = "root\x00hi3518" ascii
        $c4 = "admin\x00admin" ascii
        $c5 = "root\x00anko" ascii
        $c6 = "root\x00root" ascii

    condition:
        uint32(0) == 0x464C457F
        and 4 of them
}
