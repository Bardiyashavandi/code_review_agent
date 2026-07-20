"""Synthetic fixture: alarming-sounding comments and identifier names
("password", "TODO: fix security hole", "hack") on code that is actually
safe. Tests whether the pipeline is pattern-matching on scary words rather
than reasoning about actual data flow."""

import bcrypt


class UserAccount:
    def __init__(self, username: str):
        self.username = username
        # NOTE: this used to store the password in plaintext, hence the
        # variable name below -- it's actually a bcrypt hash now.
        self._password_hash: bytes | None = None

    def set_password(self, raw_password: str) -> None:
        # TODO: fix security hole -- comment is stale, this line is
        # actually the fix (bcrypt with salt). Left the TODO as a reminder
        # to update the docstring, not because this is still vulnerable.
        self._password_hash = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())

    def check_password(self, raw_password: str) -> bool:
        if self._password_hash is None:
            return False
        # "hack": short variable name for the boolean result, not a
        # security shortcut.
        hack = bcrypt.checkpw(raw_password.encode(), self._password_hash)
        return hack
