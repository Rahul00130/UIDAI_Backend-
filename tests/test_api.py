from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


# =========================================================
# TEST DATA
# =========================================================

TEST_EMAIL = "testuser123@example.com"
TEST_PHONE = "9123456789"
TEST_PASSWORD = "Test@1234"


# =========================================================
# ROOT API TEST
# =========================================================

def test_root():

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    assert data["status"] == "success"


# =========================================================
# REGISTER TEST
# =========================================================

def test_register():

    response = client.post(
        "/auth/register",
        json={
            "name": "Test User",
            "email": TEST_EMAIL,
            "phone": TEST_PHONE,
            "password": TEST_PASSWORD
        }
    )

    assert response.status_code in [200, 400]

    data = response.json()

    if response.status_code == 200:

        assert data["success"] is True

        assert "user_id" in data

    else:

        assert data["success"] is False

        assert "already registered" in data["message"]


# =========================================================
# DUPLICATE EMAIL TEST
# =========================================================

def test_duplicate_email():

    response = client.post(
        "/auth/register",
        json={
            "name": "Another User",
            "email": TEST_EMAIL,
            "phone": "9234567890",
            "password": TEST_PASSWORD
        }
    )

    assert response.status_code == 400

    data = response.json()

    assert data["success"] is False

    assert data["message"] == "Email already registered"


# =========================================================
# INVALID PHONE TEST
# =========================================================

def test_invalid_phone():

    response = client.post(
        "/auth/register",
        json={
            "name": "Test User",
            "email": "invalidphone@example.com",
            "phone": "123",
            "password": TEST_PASSWORD
        }
    )

    assert response.status_code == 422

    data = response.json()

    assert data["success"] is False

    assert data["error"] == "Validation Error"


# =========================================================
# INVALID PASSWORD TEST
# =========================================================

def test_invalid_password():

    response = client.post(
        "/auth/register",
        json={
            "name": "Test User",
            "email": "invalidpassword@example.com",
            "phone": "9345678901",
            "password": "test"
        }
    )

    assert response.status_code == 422

    data = response.json()

    assert data["success"] is False

    assert data["error"] == "Validation Error"


# =========================================================
# LOGIN TEST
# =========================================================

def test_login():

    response = client.post(
        "/auth/login",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    assert data["token_type"] == "bearer"

    assert "access_token" in data


# =========================================================
# WRONG LOGIN TEST
# =========================================================

def test_wrong_login():

    response = client.post(
        "/auth/login",
        json={
            "email": TEST_EMAIL,
            "password": "WrongPassword123"
        }
    )

    assert response.status_code == 401

    data = response.json()

    assert data["success"] is False

    assert data["message"] == "Invalid email or password"


# =========================================================
# UNAUTHORIZED PROFILE TEST
# =========================================================

def test_profile_without_token():

    response = client.get(
        "/auth/me"
    )

    assert response.status_code == 401


# =========================================================
# INVALID AADHAAR TEST
# =========================================================

def test_invalid_aadhaar():

    login_response = client.post(
        "/auth/login",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.post(
        "/verification/",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "aadhaar_number": "12345",
            "name": "Test User",
            "date_of_birth": "2005-01-15"
        }
    )

    assert response.status_code == 422

    data = response.json()

    assert data["success"] is False

    assert data["error"] == "Validation Error"


# =========================================================
# VERIFICATION TEST
# =========================================================

def test_verification():

    login_response = client.post(
        "/auth/login",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.post(
        "/verification/",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "aadhaar_number": "987654321098",
            "name": "Test User",
            "date_of_birth": "2005-01-15"
        }
    )

    assert response.status_code in [200, 409]

    if response.status_code == 200:

        data = response.json()

        assert data["status"] == "VERIFIED"

        assert data["masked_aadhaar"] == "XXXX-XXXX-1098"

        assert "ai_score" in data

        assert "risk_level" in data


# =========================================================
# VERIFICATION HISTORY TEST
# =========================================================

def test_verification_history():

    login_response = client.post(
        "/auth/login",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/verification/",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


# =========================================================
# USERS API TEST
# =========================================================

def test_get_users():

    response = client.get(
        "/users/"
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


# =========================================================
# USER NOT FOUND TEST
# =========================================================

def test_user_not_found():

    response = client.get(
        "/users/999999"
    )

    assert response.status_code == 404

    data = response.json()

    assert data["success"] is False

    assert data["message"] == "User not found" 