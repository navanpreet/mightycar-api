import jwt

def create_token(payload, key):
	token = jwt.encode({'user_id': payload}, key)
	return token

# def decode(token):
# 	tok = jwt.decode(token, random_string)

	
