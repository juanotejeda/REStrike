import msgpack
import requests

MSF_HOST = "127.0.0.1"
MSF_PORT = 55552
MSF_USER = "msf"
MSF_PASS = "abc123"

def msf_http_auth():
    print(f"Autenticando en {MSF_HOST}:{MSF_PORT}...")
    url = f"http://{MSF_HOST}:{MSF_PORT}/api/v1/auth/login"
    
    payload = {
        "username": MSF_USER,
        "password": MSF_PASS
    }
    
    packed_payload = msgpack.packb(payload)
    
    try:
        # Intenta con Content-Type: application/msgpack
        headers = {"Content-Type": "application/msgpack"}
        resp = requests.post(url, data=packed_payload, headers=headers, timeout=5)
        
        print(f"Status Code: {resp.status_code}")
        
        resp_data = msgpack.unpackb(resp.content, raw=False)
        print("Respuesta:", resp_data)
        
        token = resp_data.get('token')
        if token:
            print(f"✓ Token obtenido: {token}")
            return token
        else:
            print("✗ No se obtuvo token")
            return None
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()
        return None

def get_exploits_http(token):
    print("\nObteniendo exploits...")
    url = f"http://{MSF_HOST}:{MSF_PORT}/api/v1/modules/exploits"
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=10)
        
        data = msgpack.unpackb(resp.content, raw=False)
        
        if isinstance(data, dict):
            exploits = data.get('modules', [])
        else:
            exploits = data
            
        print(f"Total exploits: {len(exploits)}")
        print("Primeros 10:")
        for i, exploit in enumerate(exploits[:10]):
            print(f"  {i+1}. {exploit}")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    token = msf_http_auth()
    if token:
        get_exploits_http(token)
