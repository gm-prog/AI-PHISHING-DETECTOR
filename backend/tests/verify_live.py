import httpx
import random

c = httpx.Client(base_url='http://127.0.0.1:8000')

# Register User A and User B
u1 = c.post('/api/auth/register', json={'email': f'u1_{random.randint(1000,9999)}@test.com', 'password': 'Password123!'}).json()
u2 = c.post('/api/auth/register', json={'email': f'u2_{random.randint(1000,9999)}@test.com', 'password': 'Password123!'}).json()

tok1 = u1['access_token']
tok2 = u2['access_token']

# User A analyzes a URL
scan_a = c.post('/api/analyze', json={'input_type': 'url', 'content': 'https://github.com'}, headers={'Authorization': f'Bearer {tok1}'}).json()
hist_a = c.get('/api/history', headers={'Authorization': f'Bearer {tok1}'}).json()
scan_id = hist_a[0]['id']

# 1. User B history must be isolated (0 items)
hist_b = c.get('/api/history', headers={'Authorization': f'Bearer {tok2}'}).json()
print(f"1. User Isolation: User B sees {len(hist_b)} scans (Expected: 0)")
assert len(hist_b) == 0

# 2. User B tries IDOR to view User A's scan
idor = c.get(f'/api/history/{scan_id}', headers={'Authorization': f'Bearer {tok2}'})
print(f"2. IDOR Prevention: User B accessing User A scan -> HTTP {idor.status_code} (Expected: 403)")
assert idor.status_code == 403

# 3. User B tries to delete User A's scan
idor_del = c.delete(f'/api/history/{scan_id}', headers={'Authorization': f'Bearer {tok2}'})
print(f"3. IDOR Delete Prevention: User B deleting User A scan -> HTTP {idor_del.status_code} (Expected: 403)")
assert idor_del.status_code == 403

# 4. Standard user accesses admin route
adm_fail = c.get('/api/admin/metrics', headers={'Authorization': f'Bearer {tok2}'})
print(f"4. Admin Route Lock: Standard user accessing /api/admin/metrics -> HTTP {adm_fail.status_code} (Expected: 403)")
assert adm_fail.status_code == 403

# 5. Admin registers and accesses admin route
adm = c.post('/api/auth/register', json={'email': f'adm_{random.randint(1000,9999)}@test.com', 'password': 'Password123!', 'admin_code': 'SENTINEL_ADMIN_SECRET_2026'}).json()
adm_tok = adm['access_token']
adm_ok = c.get('/api/admin/metrics', headers={'Authorization': f'Bearer {adm_tok}'})
print(f"5. Admin RBAC: Admin accessing /api/admin/metrics -> HTTP {adm_ok.status_code} Metrics: {adm_ok.json()}")
assert adm_ok.status_code == 200

print("\n ALL LIVE END-TO-END SECURITY CHECKS PASSED!")
