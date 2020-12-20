from flask_script import Manager
from appInit import db

manager = Manager(usage = "Perform databse operations")

@manager.command
def drop():
	db.drop_all()

@manager.command
def createdb():
	db.create_all()

@manager.command
def recreate():
	drop()
	createdb()

@manager.command
def initData():
	print("iniitialization completed")


