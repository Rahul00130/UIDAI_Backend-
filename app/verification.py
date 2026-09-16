import hashlib
from datetime import datetime


def validate_aadhaar(aadhaar_number: str):

    aadhaar_number = aadhaar_number.strip()

    if len(aadhaar_number) != 12:
        return False

    if not aadhaar_number.isdigit():
        return False

    return True


def hash_aadhaar(aadhaar_number: str):

    return hashlib.sha256(
        aadhaar_number.encode("utf-8")
    ).hexdigest()


def mask_aadhaar(aadhaar_number: str):

    return "XXXX-XXXX-" + aadhaar_number[-4:]


def perform_demo_verification(
    aadhaar_number: str,
    name: str,
    date_of_birth: str
):

    aadhaar_number = aadhaar_number.strip()
    name = name.strip()
    date_of_birth = date_of_birth.strip()

    if not validate_aadhaar(aadhaar_number):

        return {
            "status": "FAILED",
            "message": "Aadhaar number must contain exactly 12 digits"
        }

    if not name:

        return {
            "status": "FAILED",
            "message": "Name cannot be empty"
        }

    if not date_of_birth:

        return {
            "status": "FAILED",
            "message": "Date of birth cannot be empty"
        }

    return {
        "status": "VERIFIED",
        "message": "Demo verification successful",
        "masked_aadhaar": mask_aadhaar(aadhaar_number),
        "aadhaar_hash": hash_aadhaar(aadhaar_number),
        "verified_at": datetime.utcnow()
    }