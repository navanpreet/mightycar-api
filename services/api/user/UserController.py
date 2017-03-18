from flask_restplus import Namespace, Resource, fields
from .UserModel import User as UserModel

api = Namespace('user', description="Everything concerning a user")

user = api.model('user', {
	'_id': fields.String(description='Unique user identifier'),
	'username': fields.String(required = True, description='Username of a user'),
	'password': fields.String(required = True, description='Password of a user'),
	'first_name': fields.String(required = True, description='First name of a user'),
	'last_name': fields.String(required = True, description='Last Name of a user'),
	'date_of_birth': fields.DateTime(required = True, description='Date of birth of a user'),
	'active': fields.Boolean(description='Is the user active'),
	'creation_date': fields.DateTime(description='Date when the user was created'),
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
	@api.marshal_list(user)
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
        '''Add a New Vehicle'''
        args = user_post.parse_args()
        data = args['data']
        del data['_id']
        newUser = UserModel.createOne(self, user)
 
        if (newUser == {}):
            api.abort(500, 'Cannot create new user')
        newUserObjectId = newUser.inserted_id
        createdUser = UserModel.getByObjectId(self, newUserObjectId)
 
        return createdUser

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
        updatedUser = UserModel.updateOne(self, id, user)
 
        if(updatedUser.matched_count == 0):
        	api.abort(404, 'Vehicle Not found')

        newDetails = UserModel.getOne(self, id)

        return newDetails

    @api.param('id', 'User id')
    @api.response(404, 'User not found')
    @api.doc('delete user')
    def delete(self, id):
    	'''Search a user by id'''
    	userDeleteCount = UserModel.delete(self, id).deleted_count
    	if(userDeleteCount == 0):
    		api.abort(404, 'User not found')
    	return {'code': 200, 'message': 'user successfully deleted'}

user_search = api.parser()
user_search.add_argument(
		'data',
		type = dict
	)