# a little trick so you can run:
# $ python example/app.py 
# from the root of the security project
import sys, os
sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from example import app
from flask.ext.script import Manager
from flask.ext.security.script import (CreateUserCommand , AddRoleCommand,
                                       RemoveRoleCommand)

manager = Manager(app.create_sqlalchemy_app())
manager.add_command('create_user', CreateUserCommand())
manager.add_command('add_role', AddRoleCommand())
manager.add_command('remove_role', RemoveRoleCommand())

if __name__ == "__main__":
    manager.run()