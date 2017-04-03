from flask_restplus import Namespace, Resource, fields
from flask import request
from .UserModel import User as UserModel
userModel = UserModel()
import sys
sys.path.append('..')
from util.JSONEncoder import JSONEncoder 
from response.respond import respond
from util.generate_tokens import create_token
import bcrypt
import random, string, json


api = Namespace('user', description="Everything concerning a user")


'''Response Marshals'''

user_output = api.model('user_output', {
    'user_id': fields.String(description='User Id'),
    'username': fields.String(description='Username of a user'),
    'first_name': fields.String(description='First name of a user'),
    'last_name': fields.String(description='Last Name of a user'),
    'email': fields.String(description='Email Address'),
    'date_of_birth': fields.DateTime(description='Date of birth of a user'),
    'active': fields.Boolean(description='Is the user active'),
    'creation_date': fields.DateTime(description='Date when the user was created'),
    'email_verified': fields.Boolean(description='Is the email verified')
    })

user_input = api.model('user_input', {
    'username': fields.String( description='Username of a user'),
    'password': fields.String( description='Password of a user'),
    'first_name': fields.String( description='First name of a user'),
    'last_name': fields.String( description='Last Name of a user'),
    'email': fields.String( description='Email Address'),
    'date_of_birth': fields.DateTime(description='Date of birth of a user'),
    })

authentication_token = api.model('authentication_token', {
    'user_id': fields.String(description="User id associated with the token"),
    'authentication_token': fields.String(),
    'salt': fields.String()
    })

verification_token = api.model('verification_token', {
    'user_id': fields.String(description="User id associated with the token"),
    'verification_token': fields.String()
    })

deletion_success = api.model('deletion_success', {
    'message': fields.String(description="Status message")
    })

login_input = api.model('user_login_input', {
    'username': fields.String( description='Username of a user'),
    'password': fields.String( description='Password of a user')
    })

login_success = api.model('login_success', {
    'user_id': fields.String( description='User id of a user'),
    'authentication_token': fields.String( description='Authentication token for a user')
    })

logout_success = api.model('logout_success', {
    'message': fields.String(description="Status message")
    })

logout_input = api.model('logout_input', {
    'user_id': fields.String(description="User Id")
    })

verification_failure = {
    'message': 'could not verify'
    }


''''''

user_get = api.parser()
user_get.add_argument('x-access-token', required=True, location='headers')   

user_post = api.parser()
user_post.add_argument('data', type=user_input)

@api.route('/')
class User(Resource):

    @api.doc('list all users')
    @api.response(200, 'Successful', user_output)
    @api.response(401, "Not authenticated")
    @api.header('x-access-token', 'authentication token', required=True)
    @api.marshal_list_with(user_output)
    def get(self):
    	'''List all users'''
        args = user_get.parse_args()
        token = args['x-access-token']
        search_token = userModel.searchAuthenticationToken(token)
        if(search_token==False):
            api.abort(401, "Not authenticated")
    	user_output = userModel.get()

        return user_output


    @api.expect(user_input)
    @api.response(200, 'User added', login_success)
    @api.response(500, 'Cannot add new user')
    @api.doc('Add a new user')
    def post(self):
        '''Add a New User'''

        args = user_post.parse_args()
        data = args['data']
        data['user_verified'] = False
        data['email_verified'] = False
        if '_id' in data:
            del data['_id']
        hashed_password = bcrypt.hashpw(str(data['password']).encode('utf8'), bcrypt.gensalt())    
        data['password'] = hashed_password
        newUser = userModel.createOne(data)

        if isinstance(newUser, dict) and 'error' in newUser.keys():
            api.abort(500, newUser['error'])
        
        newUserObjectId = newUser.inserted_id
        
        key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
        token = create_token(str(newUserObjectId), key)
        tokenObj = {
            'user_id': newUserObjectId,
            'authentication_token': token,
            'salt': key
        }
        insertedToken = userModel.createAuthenticationToken(tokenObj);
        
        # Create verification token and send email to verify user
        verificationToken = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
        verificationTokenObj = {
            'user_id': newUserObjectId,
            'verification_token': verificationToken
        }
        insertedVerificationToken = userModel.createEmailVerficationToken(verificationTokenObj)

        response = {'user_id': str(newUserObjectId), 'authentication_token': token}
            
        return response

user_put = api.parser()
user_put.add_argument('x-access-token', required=True, location='headers')
user_put.add_argument('data', type=user_input)

user_delete = api.parser()
user_delete.add_argument('x-access-token', required=True, location='headers')

@api.route('/<id>')
class UserById(Resource):


    @api.response(404, 'User not found')
    @api.response(401, "Not authenticated")
    @api.response(200, 'Successful', user_output)
    @api.doc('Get user by id')
    @api.header('x-access-token', 'authentication token', required=True)
    @api.marshal_with(user_output)
    def get(self, id):
    	'''Get a user by id'''
        token = user_get.parse_args()['x-access-token']
        search_token = userModel.searchAuthenticationToken(token)
        if(search_token==False):
            api.abort(401, "Not authenticated")
    	user_output = userModel.getOne(id)
        return user_output

    @api.expect(user_input)
    @api.response(200, 'User added', user_output)
    @api.response(500, 'Cannot update user')
    @api.response(401, "Not authenticated")
    @api.header('x-access-token', 'authentication token', required=True)
    @api.doc('update a user')
    @api.marshal_with(user_output)
    def put(self, id):
        '''Update an existing user'''
        token = user_put.parse_args()['x-access-token']
        data = user_put.parse_args()['data']
        search_token = userModel.searchAuthenticationToken(token)
        if(search_token==False):
            api.abort(401, "Not authenticated")

        updatedUser = userModel.updateOne(id, str(data))

        if(updatedUser.matched_count == 0):
        	api.abort(404, 'User Not found')

        user_output = userModel.getOne(id)
        return user_output

    @api.response(404, 'User not found')
    @api.response(200, 'User deleted', deletion_success)
    @api.header('x-access-token', 'authentication token', required=True)
    @api.doc('delete user')
    def delete(self, id):
    	'''Delete a user by id'''
        token = user_delete.parse_args()['x-access-token']
        search_token = userModel.searchAuthenticationToken(token)
        if(search_token==False):
            api.abort(401, "Not authenticated")

    	userDeleteCount = userModel.delete(id)
    	if(userDeleteCount == 0):
    		api.abort(404, 'User not found')

    	return {'message': 'Successfully deleted user'}

user_login_post = api.parser()
user_login_post.add_argument('username', required=True, location='form')
user_login_post.add_argument('password', required=True, location='form')

@api.route('/login')
class Login(Resource):

    @api.expect(user_login_post)
    @api.response(200, 'Login Successful', login_success)
    @api.response(401, 'username or password does not match')
    @api.doc('user login')
    def post(self):
        '''Accepts a username and password to create a new token'''
        args = user_login_post.parse_args()
        userData = userModel.getByUsername(args['username'])
        if bcrypt.checkpw(str(args['password']), userData['password'].encode('utf8')):
            key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
            token = create_token(str(userData['_id']), key)
            tokenObj = {
                'user_id': userData['_id'],
                'authentication_token': token,
                'salt': key
            }
            insertedToken = userModel.createAuthenticationToken(tokenObj)
            response = {'user_id': str(userData['_id']), 'authentication_token': token}
            return response 
        else:
            api.abort(401, login_failure)


logout_post = api.parser()
logout_post.add_argument('user_id', required=True)
logout_post.add_argument('x-access-token', required=True, location='headers')

@api.route('/logout')
class Logout(Resource):


    @api.response(200, 'Logout Successful', logout_success)
    @api.response(404, 'Token not found')
    @api.expect(logout_input)
    @api.header('x-access-token', 'authentication token', required=True)
    @api.doc('user logout')
    def post(self):
        token = logout_post.parse_args()['x-access-token']
        user_id = logout_post.parse_args()['user_id']
        killedToken = userModel.killToken(token)
        return logout_success

verify_get = api.parser()
verify_get.add_argument('token', location='args')

@api.route('/verify')
class Verify(Resource):
 
    @api.expect(verify_get)
    @api.response(200, 'Email verified')
    @api.response(404, 'Token not found')
    def get(self):
        '''Verify email'''
        token = verify_get.parse_args()['token']
        reset = verify_get.parse_args()['reset']
        verificationTokenLookup = userModel.searchEmailVerificationToken(token)
        if verificationTokenLookup == {}:
            return verification_failure

        userData = userModel.getOne(verificationTokenLookup['user_id'])
        userData['email_verified'] = True

        updatedUserData = userModel.updateOne(verificationTokenLookup['user_id'], userData)
        if updatedUserData == {}:
            return verification_failure

        deleteVerificationToken = userModel.deleteEmailVerificationToken(verificationTokenLookup['verification_token'])
        if deleteVerificationToken == {}:
            return verification_failure

        return {'message': 'Verified'}

forgot_post = api.parser()
forgot_post.add_argument('x-access-token', required=True, location='headers')
forgot_post.add_argument('user_id', required=True, location='form')
forgot_post.add_argument('email', required=True, location='form')

@api.route('/forgot')
class Forgot(Resource):

    @api.expect(forgot_post)
    @api.response(200, 'Email successfully sent')
    @api.response(404, 'Email not found')
    @api.response(401, 'Not authenticated')
    def post(self):
        '''Send email to reset password'''
        token = forgot_post.parse_args()['x-access-token']
        user_id = forgot_post.parse_args()['user_id']
        email = forgot_post.parse_args()['email']

        search_token = userModel.searchAuthenticationToken(token)
        
        if search_token==False:
            api.abort(401, "Not authenticated")
        if search_token['user_id'] != user_id:
            api.abort(401, "Not authenticated")

        user_output = userModel.getOne(user_id)

        if email == user_output['email']:
            tempPassword = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(8)])
            tempPasswordObj = {
                'user_id': user_id,
                'verification_token': tempPasswordObj
            }
            insertedVerificationToken = userModel.createEmailVerficationToken(verificationTokenObj)
            #send email with temp password

        else:
            api.abort(404, "Email not found")

reset_post = api.parser()
reset_post.add_argument('temp_password', required=True, location='form')
reset_post.add_argument('new_password', required=True, location='form')

@api.route('/reset')
class Reset(Resource):

    @api.response(200, 'Password successfully sent')
    @api.response(404, 'User not found')
    def post(self):
        '''Reset password'''
        temp_password = reset_post.parse_args()['temp_password']
        new_password = reset_post.parse_args()['new_password']
        tempPasswordLookup = userModel.searchEmailVerificationToken(temp_password)
        if tempPasswordLookup == {}:
            return verification_failure

        hashedPassword = bcrypt.hashpw(new_password.encode('utf8'), bcrypt.gensalt())  
        
        userData = userModel.getOne(tempPasswordObj['user_id'])

        if userData == {}:
            api.abort(404, 'User Not found')

        userData['password'] = hashedPassword

        updatedUserData = userModel.updateOne(userData['_id'], userData)

        if(updatedUser.matched_count == 0):
            api.abort(404, 'User Not found')

        return {'message': 'Password successfully reset'}











