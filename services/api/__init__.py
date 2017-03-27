from flask_restplus import Api
from .user import api as user_api

api=Api(
		title='API',
		version='1.0',
		description='Everything related to User'
	)

api.add_namespace(user_api)