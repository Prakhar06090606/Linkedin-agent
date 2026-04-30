from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health():
    res = client.get('/api/health')
    assert res.status_code == 200
    payload = res.json()
    assert payload['status'] == 'ok'


def test_generate_approve_publish_draft_flow():
    generated = client.post(
        '/api/drafts/generate',
        json={
            'topic': 'Testing end to end draft flow',
            'audience': 'developers',
            'tone': 'professional',
            'length_words': 160,
        },
    )
    assert generated.status_code == 200
    draft = generated.json()
    draft_id = draft['id']

    approve = client.post(f'/api/drafts/{draft_id}/approve')
    assert approve.status_code == 200
    assert approve.json()['status'] == 'approved'

    publish = client.post(
        f'/api/drafts/{draft_id}/publish',
        json={
            'target_url': 'https://www.linkedin.com/feed/',
            'override_title': 'Approved Test Draft',
            'override_content': 'Publishing from automated test.',
        },
    )
    assert publish.status_code in {200, 409}
    if publish.status_code == 200:
        assert 'publish' in publish.json().get('message', '').lower()


def test_manual_action_comment():
    res = client.post(
        '/api/manual/action',
        json={
            'action_type': 'comment',
            'target_url': 'https://www.linkedin.com/feed/',
            'text': 'Test comment from API test',
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data['action_type'] == 'comment'
