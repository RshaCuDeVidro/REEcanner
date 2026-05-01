"""fingerprint pelo ttl e tamanho de janela TCP"""

#admito q nao é inteligente mas confia

def guess_os(ttl, window):
    """chutar qual OS eversao baseado no ttl e tamanho da janela"""
    if ttl <= 64: itl = 64
    elif ttl <= 128: itl = 128
    else: itl = 255

    if itl == 64:
        if window in (5840, 14600, 29200, 26883, 28960, 32120, 65160):
            return "Linux"
        elif window == 65535:
            return "macOS"
        elif window in (16384, 32768):
            return "FreeBSD"
        return "Linux"
    elif itl == 128:
        return "Windows"
    elif itl == 255:
        if window in (4128, 8192):
            return "Cisco"
        return "Solaris"
    return "?"
