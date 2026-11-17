def test_audit_limit_returns_latest_rows(client, admin, invite):
    for _ in range(5):
        invite()
    response = client.get("/admin/audit?limit=2", headers=admin)
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 2
    all_rows = client.get("/admin/audit", headers=admin).json()
    assert len(all_rows) == 5
    assert [row["id"] for row in rows] == [row["id"] for row in all_rows[-2:]]
    assert [row["id"] for row in rows] == sorted(row["id"] for row in rows)
    assert client.get("/admin/audit?limit=0", headers=admin).status_code == 422
    assert client.get("/admin/audit?limit=10001", headers=admin).status_code == 422
    assert client.get("/admin/audit?limit=2").status_code == 404
