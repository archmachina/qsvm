import logging
import jinja2

import qsvm.exception as exception
import qsvm.util as util
import qsvm.core as core

logger = logging.getLogger(__name__)

def global_gen_mac(source, oui_str="525400", group_len=2, sep=":"):
    # Try to normalise the OUI
    oui_str = oui_str.replace(":", "").replace(".", "")

    # Validate the oui string
    val = int(oui_str, 16)
    if len(oui_str) != 6:
        raise exception.QSVMTemplateException("Invalid OUI suppled to global_hash_mac - Invalid length")

    # Generate a hash for the MAC
    hashval = util.generate_hash(source, 3)
    mac = oui_str + hashval

    res = ""
    index = 0
    while index < len(mac):
        res = res + mac[index:index + group_len]

        index = index + group_len
        if index < len(mac):
            res = res + sep

    return res

j2filters = {
}

j2globals = {
    "gen_mac": global_gen_mac
}

