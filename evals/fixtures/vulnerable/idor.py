"""Synthetic fixture: IDOR (Insecure Direct Object Reference) / broken
access control -- a logged-in user can access any other user's data by
changing an ID in the URL, with no ownership check."""

from flask import Flask, request, session

app = Flask(__name__)


class InvoiceDB:
    def get_by_id(self, invoice_id: int) -> dict:
        return {"id": invoice_id, "amount": 4200, "owner_id": invoice_id % 7}


db = InvoiceDB()


@app.route("/invoices/<int:invoice_id>")
def get_invoice(invoice_id: int):
    # VULNERABLE: only checks that *someone* is logged in, never that the
    # logged-in user actually owns this invoice_id. Any authenticated user
    # can enumerate /invoices/1, /invoices/2, ... and read everyone's data.
    if "user_id" not in session:
        return {"error": "not authenticated"}, 401
    invoice = db.get_by_id(invoice_id)
    return invoice


@app.route("/invoices/<int:invoice_id>/download")
def download_invoice(invoice_id: int):
    # Same missing ownership check, on a second endpoint.
    if "user_id" not in session:
        return {"error": "not authenticated"}, 401
    invoice = db.get_by_id(invoice_id)
    return {"pdf_url": f"/files/invoice_{invoice['id']}.pdf"}
