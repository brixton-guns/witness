"""Stable public error categories for the verifier and CLI."""


class WitnessError(Exception):
    """Base class for expected verification failures."""

    exit_code = 3


class InputError(WitnessError):
    """An input file cannot be read or decoded."""


class ReceiptValidationError(WitnessError):
    """A receipt is not valid Witness v0.1 data."""


class TrustError(WitnessError):
    """The supplied trusted key does not match the signed key identity."""

    exit_code = 4


class SignatureError(WitnessError):
    """The receipt signature does not verify."""

    exit_code = 4


class ArtifactMismatchError(WitnessError):
    """The supplied ledger does not match the signed artifact digest."""

    exit_code = 5
