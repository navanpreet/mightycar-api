from flask_restplus import Namespace, Resource, fields
from .UserModel import User as UserModel
userModel = UserModel()
import sys
sys.path.append('..')
from util.generate_tokens import create_token
import bcrypt
import random, string


api = Namespace('user', description="Everything concerning a user")

user = api.model('user', {
	'_id': fields.String(description='Unique user identifier'),
	'username': fields.String( description='Username of a user'),
	'password': fields.String( description='Password of a user'),
	'first_name': fields.String( description='First name of a user'),
	'last_name': fields.String( description='Last Name of a user'),
    'email': fields.String( description='Email Address'),
	'date_of_birth': fields.DateTime(description='Date of birth of a user'),
	'active': fields.Boolean(description='Is the user active'),
	'creation_date': fields.DateTime(description='Date when the user was created')
    })

authentication_token = api.model('authentication_token', {
    'user_id': fields.String(description="User id associated with the token"),
    'authentication_token': fields.String(),
    'salt': fields.String()
    })

user_login = api.model('user_login', {
    'username': fields.String( description='Username of a user'),
    'password': fields.String( description='Password of a user'),    
    })

user_post = api.parser()
user_post.add_argument(
    	'data',
    	type=user,
    	required=True			
    )

@api.route('/')
class User(Resource):

    @api.doc('list all users')
    @api.marshal_list_with(user)
    def get(self):
    	'''List all users'''
    	user = UserModel.get(self)
        return user


    @api.expect(user)
    @api.response(200, 'User added')
    @api.response(500, 'Cannot add new user')
    @api.doc('post_user')
    @api.marshal_with(user)
    def post(self):
        '''Add a New User'''
        args = user_post.parse_args()
        data = args['data']
        del data['_id']
        data['user_verified'] = False
        hashed_password = bcrypt.hashpw(str(data['password']), bcrypt.gensalt())    
        data['password'] = hashed_password
        newUser = userModel.createOne(data)

        if (newUser == {}):
            api.abort(500, 'Cannot create new user')
        newUserObjectId = newUser.inserted_id
        key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
        token = create_token(str(newUserObjectId), key)
        tokenObj = {
            'user_id': newUserObjectId,
            'authentication_token': token,
            'salt': key
        }
        insertedToken = userModel.createAuthenticationToken(tokenObj);
        createdUser = userModel.getByObjectId(newUserObjectId)
        # Create verification token and send email to verify user
        verificationToken = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
        verificationTokenObj = {
            'user_id': newUserObjectId,
            'verification_token': verificationToken
        }
        insertedVerificationToken = userModel.createEmailVerficationToken(verificationTokenObj)

        return createdUser, token

user_put = api.parser()
user_put.add_argument(
    'data',
    type=user,
    required=True		
)

@api.route('/<id>')
class UserById(Resource):

    @api.param('id', 'User Id')
    @api.response(404, 'User not found')
    @api.doc('Get user by id')
    @api.marshal_with(user)
    def get(self, id):
    	'''Get a user by id'''
    	user = UserModel.getOne(self, id)
    	return user

    @api.expect(user)
    @api.param('id', 'User id')
    @api.response(200, 'User added')
    @api.response(500, 'Cannot update new user')
    @api.doc('update user')
    @api.marshal_with(user)
    def put(self):
        '''Update an existing user'''
        args = user_put.parse_args()
        data = args['data']
        del data['_id']
        updatedUser = userModel.updateOne(self, id, user)

        if(updatedUser.matched_count == 0):
        	api.abort(404, 'Vehicle Not found')

        newDetails = userModel.getOne(self, id)

        return newDetails

    @api.param('id', 'User id')
    @api.response(404, 'User not found')
    @api.doc('delete user')
    def delete(self, id):
    	'''Search a user by id'''
    	userDeleteCount = userModel.delete(self, id).deleted_count
    	if(userDeleteCount == 0):
    		api.abort(404, 'User not found')
    	return {'code': 200, 'message': 'user successfully deleted'}

user_search = api.parser()
user_search.add_argument(
	'data',
	type=dict
)


user_login_post = api.parser()
user_login_post.add_argument(
        'data',
        type=user_login
    )

@api.route('/login')
class Login(Resource):

    @api.expect(user_login)
    @api.response(200, 'Login Successful')
    @api.response(401, 'Login Failed')
    @api.doc('user_login')
    @api.marshal_with(user_login)
    def post(self):
        '''Accepts a username and password to create a new token'''
        args = user_login.parse_args()
        data = args['data']
        del data['_id']
        
        userData = userModel.getByUsername(self, data['username'])
        if bcrypt.checkpw(data['password'], userData['password']):
            key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
            token = create_token(str(newUserObjectId), key)
            tokenObj = {
                'user_id': userData['_id'],
                'authentication_token': token,
                'salt': key
            }
            insertedToken = userModel.createAuthenticationToken(tokenObj);
            return userData['_id'], token

        else:
            return{'status': 401, 'message': 'username or password does not match'}
