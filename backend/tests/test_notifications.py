import pytest
from models import PushSubscription
from utils.push import notify_user_push
from unittest.mock import patch, MagicMock

def test_push_subscription_registration(client, db_session, user1):
    token, current_user = user1
    auth_headers = {"Authorization": f"Bearer {token}"}

    sub_data = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/fake-endpoint",
        "p256dh": "fake-p256dh",
        "auth": "fake-auth"
    }

    # Test Subscribe
    response = client.post("/notifications/subscribe", json=sub_data, headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["endpoint"] == sub_data["endpoint"]
    assert data["user_address"] == current_user["address"]

    # Verify in DB
    db_sub = db_session.query(PushSubscription).filter_by(endpoint=sub_data["endpoint"]).first()
    assert db_sub is not None
    assert db_sub.user_address == current_user["address"]

def test_notify_user_push_logic(db_session, user1):
    token, current_user = user1
    
    # Add a subscription
    sub = PushSubscription(
        user_address=current_user["address"],
        endpoint="https://fake.endpoint",
        p256dh="p256",
        auth="auth"
    )
    db_session.add(sub)
    db_session.commit()

    # Mock webpush to avoid external calls
    with patch("utils.push.webpush") as mock_webpush:
        notify_user_push(db_session, current_user["address"], "Title", "Body", {"key": "val"})
        
        # Verify it was called
        assert mock_webpush.called
        args, kwargs = mock_webpush.call_args
        assert kwargs["subscription_info"]["endpoint"] == "https://fake.endpoint"
        assert "Title" in kwargs["data"]
        assert "Body" in kwargs["data"]

def test_push_cleanup_on_gone(db_session, user1):
    token, current_user = user1
    
    # Add a subscription
    sub = PushSubscription(
        user_address=current_user["address"],
        endpoint="https://gone.endpoint",
        p256dh="p256",
        auth="auth"
    )
    db_session.add(sub)
    db_session.commit()

    # Mock WebPushException with 410 Gone
    from pywebpush import WebPushException
    mock_response = MagicMock()
    mock_response.status_code = 410
    
    with patch("utils.push.webpush", side_effect=WebPushException("Gone", response=mock_response)):
        notify_user_push(db_session, current_user["address"], "Title", "Body")
        
        # Verify subscription was deleted
        db_sub = db_session.query(PushSubscription).filter_by(endpoint="https://gone.endpoint").first()
        assert db_sub is None
