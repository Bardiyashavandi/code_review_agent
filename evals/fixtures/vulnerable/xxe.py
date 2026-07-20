"""Synthetic fixture: XXE via unsafe XML parsing of untrusted input."""

from flask import Flask, request
from xml.etree import ElementTree as ET

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    xml_body = request.data
    # VULNERABLE: ElementTree.fromstring resolves external entities by
    # default in the stdlib -- an attacker can read local files or trigger
    # SSRF via a crafted <!ENTITY> declaration.
    root = ET.fromstring(xml_body)
    return {"root_tag": root.tag}
