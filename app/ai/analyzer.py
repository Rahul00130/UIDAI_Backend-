from datetime import datetime


def analyze_verification(
    aadhaar_number: str,
    name: str,
    date_of_birth: str
):

    score = 100
    issues = []
    suggestions = []

    aadhaar_number = aadhaar_number.strip()
    name = name.strip()
    date_of_birth = date_of_birth.strip()

    if len(aadhaar_number) != 12:
        score -= 40
        issues.append("Aadhaar number must contain 12 digits")

    if not aadhaar_number.isdigit():
        score -= 40
        issues.append("Aadhaar number must contain only digits")

    if not name:
        score -= 20
        issues.append("Name is missing")

    elif len(name) < 3:
        score -= 10
        issues.append("Name is too short")

    if not date_of_birth:
        score -= 20
        issues.append("Date of birth is missing")

    else:

        try:

            datetime.strptime(
                date_of_birth,
                "%Y-%m-%d"
            )

        except ValueError:

            score -= 20

            issues.append(
                "Date of birth must use YYYY-MM-DD format"
            )

    if score >= 90:

        risk_level = "LOW"

        suggestions.append(
            "Verification data looks complete"
        )

    elif score >= 60:

        risk_level = "MEDIUM"

        suggestions.append(
            "Review the submitted information"
        )

    else:

        risk_level = "HIGH"

        suggestions.append(
            "Correct the submitted information"
        )

    return {
        "score": max(score, 0),
        "risk_level": risk_level,
        "issues": issues,
        "suggestions": suggestions
    } 