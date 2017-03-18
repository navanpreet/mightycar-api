from  flask import flask
from flask_pymongo import *
from flask import json
from bson.objectid import ObjectId
import json
from ..util.JSONEncoder import JSONEncoder
import json
from ..config import mongo

app = Flask(__name__)

app.config['MONGO_HOST'] = mongo['MONGO_HOST']
app.config['MONGO_PORT'] = mongo['MONGO_PORT']
app.config['MONGO_DBNAME'] = mongo['MONGO_DBNAME']

mongo = PyMongo(app, config_prefix="MONGO")

class User():

	def getOne(self, id):
		userResult = mongo.db.user.find_one({'_id': ObjectId(id)})
		if userResult == None:
			return {}

		return userResult


	def getByObjectId(self, objectId):
		userResult = mongo.db.user.find_one({'_id': objectId})
		if userResult == None:
			return {}

		return userResult

	def get(self):
		users = mongo.db.user.find({})
		if users == None:
			return []

		return list(users)

    def createOne(self, userData):
        newUser = mongo.db.user.insert_one(userData)
        if (newUser == None):
                return {}

        return newUser

    def updateOne(self, id, userData):
        updatedUser = mongo.db.user.update_one({'_id':ObjectId(id)}, {"$set": userData})
        if (updatedUser == None):
            return {}

        return updatedUser
 
    def delete(self, id):
        deletedUser = mongo.db.user.delete_one({'_id': ObjectId(id)})
 
        return deletedUser
 
    def search(self, criteria):
        users = mongo.db.vehicle.find(criteria)
        if (users == None):
            return []
 
        return json.loads(JSONEncoder().encode(list(users)))		